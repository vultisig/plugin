package payroll

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/vultiserver/contexthelper"
	"golang.org/x/sync/errgroup"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/scheduler"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/types"
)

func (p *Plugin) HandleSchedulerTrigger(c context.Context, t *asynq.Task) error {
	ctx, cancel := context.WithTimeout(c, 5*time.Minute)
	defer cancel()

	if err := contexthelper.CheckCancellation(ctx); err != nil {
		p.logger.WithError(err).Warn("Context cancelled, skipping scheduler trigger")
		return err
	}
	var trigger types.TimeTrigger
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
		return fmt.Errorf("p.ProposeTransactions: %s, %w", err, asynq.SkipRetry)
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
		return fmt.Errorf("eg.Wait: %s, %w", err, asynq.SkipRetry)
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
		return fmt.Errorf("p.signer.Sign: %w", err)
	}

	if len(sigs) != 1 {
		p.logger.
			WithField("sigs_count", len(sigs)).
			Error("expected only 1 message+sig per request for evm")
		return fmt.Errorf("p.signer.Sign: %w", err)
	}
	var sig tss.KeysignResponse
	for _, s := range sigs {
		sig = s
	}

	err = p.SigningComplete(ctx, sig, req, pluginPolicy)
	if err != nil {
		p.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("p.SigningComplete: %w", err)
	}

	p.logger.WithField("public_key", req.PublicKey).
		Info("successfully signed and broadcasted")
	return nil
}

func (p *Plugin) IsAlreadyProposed(
	ctx context.Context,
	frequency rtypes.ScheduleFrequency,
	startTime time.Time,
	interval int,
	chainID vcommon.Chain,
	pluginID vtypes.PluginID,
	policyID uuid.UUID,
	tokenID, recipientPublicKey string,
) (bool, error) {
	sched, err := scheduler.NewIntervalSchedule(
		frequency,
		startTime,
		interval,
	)
	if err != nil {
		return false, fmt.Errorf("scheduler.NewIntervalSchedule: %w", err)
	}

	fromTime, toTime := sched.ToRangeFrom(time.Now())

	_, err = p.txIndexerService.GetTxInTimeRange(
		ctx,
		chainID,
		pluginID,
		policyID,
		tokenID,
		recipientPublicKey,
		fromTime,
		toTime,
	)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, storage.ErrNoTx) {
		return false, nil
	}
	return false, fmt.Errorf("p.txIndexerService.GetTxInTimeRange: %w", err)
}

func getTokenID(rule *rtypes.Rule) (string, error) {
	if rule == nil {
		return "", fmt.Errorf("rule is nil")
	}

	for _, constraint := range rule.GetParameterConstraints() {
		if constraint.ParameterName == "token" {
			return constraint.GetConstraint().GetFixedValue(), nil
		}
	}
	return evm.ZeroAddress.Hex(), nil
}

func (p *Plugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	ctx := context.Background()

	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	vault, err := common.GetVaultFromPolicy(p.vaultStorage, policy, p.vaultEncryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from policy: %v", err)
	}

	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vcommon.Ethereum)
	if err != nil {
		return nil, fmt.Errorf("failed to get eth address: %v", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe from policy: %v", err)
	}

	chain := vcommon.Ethereum
	ethEvmID, err := chain.EvmID()
	if err != nil {
		return nil, fmt.Errorf("failed to get EVM ID for chain %s: %v", chain, err)
	}

	schedule := recipe.Schedule

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group

	for _, _rule := range recipe.Rules {
		rule := _rule

		tokenID, er := getTokenID(rule)
		if er != nil {
			return nil, fmt.Errorf("getTokenID: %v", er)
		}

		recipients, amountStr, er := RuleToRecipientsAndAmount(rule)
		if er != nil {
			return nil, fmt.Errorf("failed to get recipients and amount: %v", er)
		}

		for _, _recipient := range recipients {
			recipient := _recipient

			eg.Go(func() error {
				isAlreadyProposed, e := p.IsAlreadyProposed(
					ctx,
					schedule.Frequency,
					schedule.StartTime.AsTime(),
					int(schedule.Interval),
					chain,
					policy.PluginID,
					policy.ID,
					tokenID,
					recipient,
				)
				if e != nil {
					return fmt.Errorf("p.IsAlreadyProposed: %w", e)
				}
				if isAlreadyProposed {
					p.logger.WithFields(logrus.Fields{
						"recipient": recipient,
						"amount":    amountStr,
						"chain_id":  chain,
						"token_id":  tokenID,
					}).Info("transaction already proposed, skipping")
					return nil
				}

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

				txHex := gcommon.Bytes2Hex(tx)

				txData, e := ethereum.DecodeUnsignedPayload(tx)
				if e != nil {
					return fmt.Errorf("ethereum.DecodeUnsignedPayload: %w", e)
				}
				txHashToSign := etypes.LatestSignerForChainID(ethEvmID).Hash(etypes.NewTx(txData))

				txToTrack, e := p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
					PluginID:      policy.PluginID,
					PolicyID:      policy.ID,
					ChainID:       chain,
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
								Chain:        chain,
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
		gcommon.FromHex(signRequest.Transaction),
		gcommon.Hex2Bytes(signature.R),
		gcommon.Hex2Bytes(signature.S),
		gcommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		p.logger.WithError(err).WithField("tx_hex", signRequest.Transaction).Error("p.eth.Send")
		return fmt.Errorf("p.eth.Send(tx_hex=%s): %w", signRequest.Transaction, err)
	}

	p.logger.WithField("hash", tx.Hash().Hex()).Info("transaction successfully broadcasted")
	return nil
}

func (p *Plugin) GetRecipeSpecification() *rtypes.RecipeSchema {
	return &rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		PluginId:        string(vtypes.PluginVultisigPayroll_0000),
		PluginName:      "Payroll Management",
		PluginVersion:   1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "erc20",
					FunctionId: "transfer",
					Full:       "ethereum.erc20.transfer",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "recipient",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						},
						Required: true,
					},
					{
						ParameterName: "token", // ERC20/TRC20/etc contract address
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						},
						Required: true,
					},
				},
				Required: true,
			},
		},
		Scheduling: &rtypes.SchedulingCapability{
			SupportsScheduling: true,
			SupportedFrequencies: []rtypes.ScheduleFrequency{
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY,
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_BIWEEKLY,
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY,
			},
			MaxScheduledExecutions: -1, // infinite
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}

func (p *Plugin) genUnsignedTx(
	ctx context.Context,
	chain vcommon.Chain,
	senderAddress, tokenID, amount, to string,
) ([]byte, error) {
	switch chain {
	case vcommon.Ethereum:
		amt, ok := new(big.Int).SetString(amount, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse amount: %s", amount)
		}

		tx, err := p.eth.MakeAnyTransfer(
			ctx,
			gcommon.HexToAddress(senderAddress),
			gcommon.HexToAddress(to),
			gcommon.HexToAddress(tokenID),
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

func RuleToRecipientsAndAmount(rule *rtypes.Rule) ([]string, string, error) {
	var recipients []string
	var amountStr string

	if len(rule.ParameterConstraints) == 0 {
		return nil, "", fmt.Errorf("no parameter constraints found")
	}

	if len(rule.ParameterConstraints) > 3 {
		return nil, "", fmt.Errorf("too many parameter constraints found")
	}

	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "recipient" {
			switch constraint.Constraint.Type {
			case rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED:
				recipients = []string{constraint.Constraint.GetFixedValue()}
			case rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST:
				recipients = constraint.Constraint.GetWhitelistValues().GetValues()
			}

		}

		if constraint.ParameterName == "amount" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return nil, "", fmt.Errorf("amount constraint is not a fixed value")
			}

			fixedValue := constraint.Constraint.GetValue().(*rtypes.Constraint_FixedValue)
			amountStr = fixedValue.FixedValue
		}
	}

	return recipients, amountStr, nil
}
