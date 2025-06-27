package payroll

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/recipes/chain"
	reth "github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/sdk/evm"
	rutil "github.com/vultisig/recipes/util"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/vultiserver/contexthelper"
	"golang.org/x/sync/errgroup"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/types"
)

// TODO: remove once the plugin installation is implemented
const (
	hexEncryptionKey = "hexencryptionkey"
)

func (p *PayrollPlugin) HandleSchedulerTrigger(c context.Context, t *asynq.Task) error {
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

	reqs, err := p.ProposeTransactions(pluginPolicy)
	if err != nil {
		p.logger.WithError(err).Error("p.ProposeTransactions")
		return fmt.Errorf("p.ProposeTransactions: %s, %w", err, asynq.SkipRetry)
	}

	var eg errgroup.Group
	for _, _req := range reqs {
		req := _req
		eg.Go(func() error {
			return p.initSign(ctx, req, pluginPolicy)
		})
	}
	err = eg.Wait()
	if err != nil {
		p.logger.WithError(err).Error("eg.Wait")
		return fmt.Errorf("eg.Wait: %s, %w", err, asynq.SkipRetry)
	}

	return nil
}

func (p *PayrollPlugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
) error {
	buf, e := json.Marshal(req)
	if e != nil {
		p.logger.WithError(e).Error("json.Marshal")
		return fmt.Errorf("json.Marshal: %w", e)
	}

	task, e := p.client.Enqueue(
		asynq.NewTask(tasks.TypeKeySignDKLS, buf),
		asynq.MaxRetry(0),
		asynq.Timeout(5*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME),
	)
	if e != nil {
		p.logger.WithError(e).Error("p.client.Enqueue")
		return fmt.Errorf("p.client.Enqueue: %w", e)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
			taskInfo, er := p.inspector.GetTaskInfo(tasks.QUEUE_NAME, task.ID)
			if er != nil {
				p.logger.WithError(er).Error("p.inspector.GetTaskInfo(tasks.QUEUE_NAME, task.ID)")
				return fmt.Errorf("p.inspector.GetTaskInfo: %w", er)
			}
			if taskInfo.State != asynq.TaskStateCompleted {
				continue
			}
			if taskInfo.Result == nil {
				p.logger.Info("taskInfo.Result is nil, skipping")
				return nil
			}

			var res map[string]tss.KeysignResponse
			er = json.Unmarshal(taskInfo.Result, &res)
			if er != nil {
				p.logger.WithError(er).Error("json.Unmarshal(taskInfo.Result, &res)")
				return fmt.Errorf("json.Unmarshal(taskInfo.Result, &res): %w", er)
			}

			var sig tss.KeysignResponse
			for _, v := range res { // one sig for evm (map with 1 key)
				sig = v
			}

			er = p.SigningComplete(ctx, sig, req, pluginPolicy)
			if er != nil {
				p.logger.WithError(er).Error("p.SigningComplete")
				return fmt.Errorf("p.SigningComplete: %w", er)
			}

			p.logger.WithField("public_key", req.PublicKey).
				Info("successfully signed and broadcasted")
			return nil
		}
	}
}

func (p *PayrollPlugin) IsAlreadyProposed(
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

func (p *PayrollPlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	ctx := context.Background()

	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	vault, err := common.GetVaultFromPolicy(p.vaultStorage, policy, p.encryptionSecret)
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

	echain, err := chain.GetChain("ethereum")
	if err != nil {
		return nil, fmt.Errorf("failed to get ethereum chain: %v", err)
	}

	ethchain := echain.(*reth.Ethereum)

	chain := vcommon.Ethereum

	schedule := recipe.Schedule

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group

	for _, rule := range recipe.Rules {
		resourcePath, err := rutil.ParseResource(rule.Resource)
		if err != nil {
			return nil, fmt.Errorf("failed to parse resource: %v", err)
		}

		var tokenID string
		if strings.ToLower(resourcePath.ProtocolId) == "eth" {
			tokenID = evm.ZeroAddress.Hex()
		} else {
			token, found := ethchain.GetToken(resourcePath.ProtocolId)
			if !found {
				return nil, fmt.Errorf("failed to get token: %v", resourcePath.ProtocolId)
			}
			tokenID = token.Address
		}

		recipient, amountStr, err := RuleToRecipientAndAmount(rule)
		if err != nil {
			return nil, fmt.Errorf("failed to get recipient and amount: %v", err)
		}

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

			// Create signing request
			signRequest := vtypes.PluginKeysignRequest{
				KeysignRequest: vtypes.KeysignRequest{
					PublicKey: policy.PublicKey,
					Messages: []vtypes.KeysignMessage{
						{
							TxIndexerID: txToTrack.ID.String(),
							Message:     txHex,
							Chain:       vcommon.Ethereum,
							// Doesn't make sense to compute hash with empty V,R,S,
							// not on-chain hash without signature
							Hash: txHex,
						},
					},
					SessionID:        uuid.New().String(),
					HexEncryptionKey: hexEncryptionKey,
					PolicyID:         policy.ID,
					PluginID:         policy.PluginID.String(),
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

func (p *PayrollPlugin) SigningComplete(
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

func (p *PayrollPlugin) GetRecipeSpecification() rtypes.RecipeSchema {
	return rtypes.RecipeSchema{
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
						ParameterName: "token",
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
			MaxScheduledExecutions: 100, // Reasonable limit for payroll runs
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}

func (p *PayrollPlugin) genUnsignedTx(
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

func RuleToRecipientAndAmount(rule *rtypes.Rule) (string, string, error) {
	var recipient string
	var amountStr string

	if len(rule.ParameterConstraints) == 0 {
		return "", "", fmt.Errorf("no parameter constraints found")
	}

	if len(rule.ParameterConstraints) > 2 {
		return "", "", fmt.Errorf("too many parameter constraints found")
	}

	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "recipient" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return "", "", fmt.Errorf("recipient constraint is not a fixed value")
			}

			fixedValue := constraint.Constraint.GetValue().(*rtypes.Constraint_FixedValue)
			recipient = fixedValue.FixedValue
		}

		if constraint.ParameterName == "amount" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return "", "", fmt.Errorf("amount constraint is not a fixed value")
			}

			fixedValue := constraint.Constraint.GetValue().(*rtypes.Constraint_FixedValue)
			amountStr = fixedValue.FixedValue
		}
	}

	return recipient, amountStr, nil
}
