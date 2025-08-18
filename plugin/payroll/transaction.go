package payroll

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	ecommon "github.com/ethereum/go-ethereum/common"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/recipes/util"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultiserver/contexthelper"
	"github.com/vultisig/vultisig-go/address"
	vgcommon "github.com/vultisig/vultisig-go/common"
	"golang.org/x/sync/errgroup"

	"github.com/vultisig/plugin/common"
)

func (p *Plugin) HandleSchedulerTrigger(c context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(c, 5*time.Minute)
	defer cancel()

	if err := contexthelper.CheckCancellation(ctx); err != nil {
		p.logger.WithError(err).Warn("Context cancelled, skipping scheduler trigger")
		return err
	}
	var trigger scheduler.Scheduler
	if err := json.Unmarshal(t.Payload(), &trigger); err != nil {
		p.logger.WithError(err).Error("Failed to unmarshal trigger payload")
		return fmt.Errorf("failed to unmarshal trigger payload: %s, %w", err, asynq.SkipRetry)
	}
	pluginPolicy, err := p.db.GetPluginPolicy(ctx, trigger.PolicyID)
	if err != nil {
		p.logger.WithError(err).Error("Failed to get plugin policy from database")
		return fmt.Errorf("failed to get plugin policy: %s, %w", err, asynq.SkipRetry)
	}

	reqs, err := p.ProposeTransactions(*pluginPolicy)
	if err != nil {
		p.logger.WithError(err).Error("p.ProposeTransactions")
		return fmt.Errorf("failed to propose transactions: %s, %w", err, asynq.SkipRetry)
	}

	var eg errgroup.Group
	for _, _req := range reqs {
		req := _req
		eg.Go(func() error {
			return p.initSign(ctx, req, *pluginPolicy)
		})
	}
	err = eg.Wait()
	if err != nil {
		p.logger.WithError(err).Error("eg.Wait")
		return fmt.Errorf("failed to wait for signing tasks: %s, %w", err, asynq.SkipRetry)
	}

	return nil
}

func (p *Plugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
) error {
	sigs, err := p.signer.Sign(ctx, req)
	if err != nil {
		p.logger.WithError(err).Error("Keysign failed")
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	if len(sigs) != 1 {
		p.logger.
			WithField("sigs_count", len(sigs)).
			Error("expected only 1 message+sig per request for evm")
		return fmt.Errorf("failed to sign transaction: invalid signature count: %d", len(sigs))
	}
	var sig tss.KeysignResponse
	for _, s := range sigs {
		sig = s
	}

	err = p.SigningComplete(ctx, sig, req, pluginPolicy)
	if err != nil {
		p.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("failed to complete signing process: %w", err)
	}
	return nil
}

func (p *Plugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	ctx := context.Background()

	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to validate plugin policy: %w", err)
	}

	vault, err := common.GetVaultFromPolicy(p.vaultStorage, policy, p.vaultEncryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from policy: %w", err)
	}

	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vgcommon.Ethereum)
	if err != nil {
		return nil, fmt.Errorf("failed to get eth address: %w", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe from policy: %w", err)
	}

	chain := vgcommon.Ethereum
	ethEvmID, err := chain.EvmID()
	if err != nil {
		return nil, fmt.Errorf("failed to get EVM ID for chain %s: %w", chain, err)
	}
	nativeSymbol, err := chain.NativeSymbol()
	if err != nil {
		return nil, fmt.Errorf("failed to get native symbol for chain %s: %w", chain, err)
	}

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group

	for _, _rule := range recipe.Rules {
		rule := _rule

		resource, er := util.ParseResource(rule.GetResource())
		if er != nil {
			return nil, fmt.Errorf("failed to parse resource: %w", er)
		}

		var tokenID string
		switch resource.GetProtocolId() {
		case nativeSymbol:
			tokenID = evm.ZeroAddress.Hex()
		default:
			tokenID = rule.GetTarget().GetAddress()
		}

		recipient, amountStr, er := RuleToRecipientAndAmount(rule)
		if er != nil {
			return nil, fmt.Errorf("failed to get recipient and amount: %v", er)
		}

		eg.Go(func() error {
			tx, e := p.genUnsignedTx(
				ctx,
				chain,
				ethAddress,
				tokenID,
				amountStr,
				recipient,
			)
			if e != nil {
				return fmt.Errorf("p.genUnsignedTx: %w", e)
			}

			txHex := ecommon.Bytes2Hex(tx)

			txData, e := ethereum.DecodeUnsignedPayload(tx)
			if e != nil {
				return fmt.Errorf("ethereum.DecodeUnsignedPayload: %w", e)
			}
			txHashToSign := etypes.LatestSignerForChainID(ethEvmID).Hash(etypes.NewTx(txData))

			txToTrack, e := p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
				PluginID:      policy.PluginID,
				PolicyID:      policy.ID,
				ChainID:       vgcommon.Chain(chain),
				TokenID:       tokenID,
				FromPublicKey: policy.PublicKey,
				ToPublicKey:   recipient,
				ProposedTxHex: txHex,
			})
			if e != nil {
				return fmt.Errorf("p.txIndexerService.CreateTx: %w", e)
			}

			msgHash := sha256.Sum256(txHashToSign.Bytes())

			// Create signing request
			signRequest := vtypes.PluginKeysignRequest{
				KeysignRequest: vtypes.KeysignRequest{
					PublicKey: policy.PublicKey,
					Messages: []vtypes.KeysignMessage{
						{
							TxIndexerID:  txToTrack.ID.String(),
							Message:      base64.StdEncoding.EncodeToString(txHashToSign.Bytes()),
							Chain:        vgcommon.Chain(chain),
							Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
							HashFunction: vtypes.HashFunction_SHA256,
						},
					},
					PolicyID: policy.ID,
					PluginID: policy.PluginID.String(),
				},
				Transaction: txHex,
			}

			mu.Lock()
			txs = append(txs, signRequest)
			mu.Unlock()
			return nil
		})
	}

	err = eg.Wait()
	if err != nil {
		p.logger.Errorf("eg.Wait: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("eg.Wait: %w", err)
	}

	return txs, nil
}

func (p *Plugin) SigningComplete(
	ctx context.Context,
	signature tss.KeysignResponse,
	signRequest vtypes.PluginKeysignRequest,
	_ vtypes.PluginPolicy,
) error {
	tx, err := p.eth.Send(
		ctx,
		ecommon.FromHex(signRequest.Transaction),
		ecommon.Hex2Bytes(signature.R),
		ecommon.Hex2Bytes(signature.S),
		ecommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		p.logger.WithError(err).WithField("tx_hex", signRequest.Transaction).Error("p.eth.Send")
		return fmt.Errorf("p.eth.Send(tx_hex=%s): %w", signRequest.Transaction, err)
	}

	p.logger.WithFields(logrus.Fields{
		"from_public_key": signRequest.PublicKey,
		"to_address":      tx.To().Hex(),
		"hash":            tx.Hash().Hex(),
		"chain":           vgcommon.Ethereum.String(),
	}).Info("tx successfully signed and broadcasted")
	return nil
}

const (
	startDate = "startDate"
)

const (
	frequency = "frequency"

	daily    = "daily"
	weekly   = "weekly"
	biWeekly = "bi-weekly"
	monthly  = "monthly"
)

func (p *Plugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	cfg, err := plugin.RecipeConfiguration(map[string]any{
		"type": "object",
		"properties": map[string]any{
			startDate: map[string]any{
				"type":   "string",
				"format": "date-time",
			},
			frequency: map[string]any{
				"type": "string",
				"enum": []any{
					daily,
					weekly,
					biWeekly,
					monthly,
				},
			},
		},
		"required": []any{
			frequency,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

	return &rtypes.RecipeSchema{
		Version:       1, // Schema version
		PluginId:      string(vtypes.PluginVultisigPayroll_0000),
		PluginName:    "Payroll Management",
		PluginVersion: 1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "erc20",
					FunctionId: "transfer",
					Full:       "ethereum.erc20.transfer",
				},
				Target: rtypes.TargetType_TARGET_TYPE_ADDRESS,
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName:  "recipient",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						Required:       true,
					},
					{
						ParameterName:  "amount",
						SupportedTypes: rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						Required:       true,
					},
				},
				Required: true,
			},
		},
		Configuration: cfg,
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}, nil
}

func (p *Plugin) genUnsignedTx(
	ctx context.Context,
	chain vgcommon.Chain,
	senderAddress, tokenID, amount, to string,
) ([]byte, error) {
	switch chain {
	case vgcommon.Ethereum:
		amt, ok := new(big.Int).SetString(amount, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse amount: %s", amount)
		}

		tx, err := p.eth.MakeAnyTransfer(
			ctx,
			ecommon.HexToAddress(senderAddress),
			ecommon.HexToAddress(to),
			ecommon.HexToAddress(tokenID),
			amt,
		)
		if err != nil {
			return nil, fmt.Errorf("p.eth.MakeAnyTransfer: %v", err)
		}
		return tx, nil
	default:
	}
	return nil, fmt.Errorf("unsupported chain: %s", chain)
}

func RuleToRecipientAndAmount(rule *rtypes.Rule) (string, string, error) {
	if len(rule.ParameterConstraints) == 0 {
		return "", "", fmt.Errorf("no parameter constraints found")
	}

	if len(rule.ParameterConstraints) > 3 {
		return "", "", fmt.Errorf("too many parameter constraints found")
	}

	var (
		recipient string
		amountStr string
	)
	for _, constraint := range rule.ParameterConstraints {
		if recipient != "" && amountStr != "" {
			break
		}

		if constraint.ParameterName == "recipient" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return "", "", fmt.Errorf("recipient constraint is not a fixed value")
			}
			recipient = constraint.Constraint.GetFixedValue()
		}

		if constraint.ParameterName == "amount" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return "", "", fmt.Errorf("amount constraint is not a fixed value")
			}
			amountStr = constraint.Constraint.GetFixedValue()
		}
	}

	return recipient, amountStr, nil
}
