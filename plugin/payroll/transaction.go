package payroll

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vultisig/plugin/internal/scheduler"
	reth "github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/vultiserver/contexthelper"
	"golang.org/x/sync/errgroup"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	gcommon "github.com/ethereum/go-ethereum/common"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
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

var ethereumEvmChainID = big.NewInt(1)

// consider as native evm chain asset — ETH,BNB,ARB etc
var evmZeroAddress = gcommon.HexToAddress("0x0000000000000000000000000000000000000000")

func (p *PayrollPlugin) HandleSchedulerTrigger(ctx context.Context, t *asynq.Task) error {
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
	// propose transaction and get it signed
	_ = pluginPolicy
	return nil
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

	var payrollPolicy PayrollPolicy
	// TODO: convert the recipes to PayrollPolicy

	chain := vcommon.Ethereum

	schedule, err := payrollPolicy.Schedule.Typed()
	if err != nil {
		p.logger.WithError(err).Error("payrollPolicy.Schedule.Typed")
		return nil, fmt.Errorf("payrollPolicy.Schedule.Typed: %w", err)
	}

	var (
		mu  = &sync.Mutex{}
		txs = make([]vtypes.PluginKeysignRequest, 0)
	)
	var eg errgroup.Group
	for _i, _recipient := range payrollPolicy.Recipients {
		i := _i
		recipient := _recipient

		eg.Go(func() error {
			isAlreadyProposed, e := p.IsAlreadyProposed(
				ctx,
				schedule.Frequency,
				schedule.StartTime,
				schedule.Interval,
				chain,
				policy.PluginID,
				policy.ID,
				payrollPolicy.TokenID[i],
				recipient.Address,
			)
			if e != nil {
				return fmt.Errorf("p.IsAlreadyProposed: %w", e)
			}
			if isAlreadyProposed {
				p.logger.WithFields(logrus.Fields{
					"recipient": recipient.Address,
					"amount":    recipient.Amount,
					"chain_id":  payrollPolicy.ChainID[i],
					"token_id":  payrollPolicy.TokenID[i],
				}).Info("transaction already proposed, skipping")
				return nil
			}

			tx, e := p.genUnsignedTx(
				ctx,
				chain,
				policy.PublicKey,
				payrollPolicy.TokenID[i],
				recipient.Amount,
				recipient.Address,
			)
			if e != nil {
				return fmt.Errorf("p.genUnsignedTx: %w", e)
			}

			txHex := hex.EncodeToString(tx)

			// Create signing request
			signRequest := vtypes.PluginKeysignRequest{
				KeysignRequest: vtypes.KeysignRequest{
					PublicKey: policy.PublicKey,
					Messages: []vtypes.KeysignMessage{
						{
							Message: txHex,
							Chain:   vcommon.Ethereum,
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

			_, e = p.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
				PluginID:      policy.PluginID,
				PolicyID:      policy.ID,
				ChainID:       chain,
				TokenID:       payrollPolicy.TokenID[i],
				FromPublicKey: policy.PublicKey,
				ToPublicKey:   recipient.Address,
				ProposedTxHex: signRequest.Transaction,
			})
			if e != nil {
				p.logger.WithError(e).Error("p.txIndexerService.CreateTx")
				return fmt.Errorf("p.txIndexerService.CreateTx: %w", e)
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

	signRequest := txs[0]
	txBytes, err := hex.DecodeString(signRequest.Transaction)
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to decode transaction hex: %w", err)
	}
	// unmarshal tx from sign req.transaction
	tx := &gtypes.Transaction{}
	err = tx.UnmarshalBinary(txBytes)
	if err != nil {
		p.logger.Errorf("Failed to unmarshal transaction: %v", err)
		return []vtypes.PluginKeysignRequest{}, fmt.Errorf("failed to unmarshal transaction: %w:", err)
	}

	return txs, nil
}

func (p *PayrollPlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	tx, err := evmAppendSignature(ethereumEvmChainID, gcommon.FromHex(signRequest.Transaction), signature)
	if err != nil {
		p.logger.WithError(err).Error("evmAppendSignature")
		return fmt.Errorf("evmAppendSignature: %w", err)
	}

	sender, err := address.GetEVMAddress(signRequest.PublicKey)
	if err != nil {
		p.logger.WithError(err).Error("address.GetEVMAddress")
		return fmt.Errorf("address.GetEVMAddress: %w", err)
	}

	err = p.rpcClient.SendTransaction(ctx, tx)
	if err != nil {
		p.logger.WithError(err).Error("Failed to broadcast transaction")
		return p.handleBroadcastError(err, gcommon.HexToAddress(sender))
	}

	p.logger.WithField("hash", tx.Hash().Hex()).Info("Transaction successfully broadcast")

	return p.monitorTransaction(tx)
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
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX,
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX_PER_PERIOD,
						},
						Required: true,
					},
					{
						ParameterName: "token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
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
	senderPublicKey, tokenID, amount, to string,
) ([]byte, error) {
	switch chain {
	case vcommon.Ethereum:
		tx, err := p.evmMakeUnsignedTransfer(
			ctx,
			ethereumEvmChainID,
			senderPublicKey,
			tokenID,
			amount,
			to,
		)
		if err != nil {
			return nil, fmt.Errorf("p.evmMakeUnsignedTransfer: %v", err)
		}
		return tx, nil
	default:
	}
	return nil, fmt.Errorf("unsupported chain: %s", chain)
}

func evmEncodeUnsignedDynamicFeeTx(
	evmChainID *big.Int,
	nonce uint64,
	to gcommon.Address,
	maxPriorityFeePerGas, maxFeePerGas *big.Int,
	gas uint64,
	value *big.Int,
	data []byte,
	accessList gtypes.AccessList,
) ([]byte, error) {
	bytes, err := rlp.EncodeToBytes(reth.DynamicFeeTxWithoutSignature{
		ChainID:    evmChainID,
		Nonce:      nonce,
		GasTipCap:  maxPriorityFeePerGas,
		GasFeeCap:  maxFeePerGas,
		Gas:        gas,
		To:         &to,
		Value:      value,
		Data:       data,
		AccessList: accessList,
	})
	if err != nil {
		return nil, fmt.Errorf("rlp.EncodeToBytes: %v", err)
	}

	res := append([]byte{gtypes.DynamicFeeTxType}, bytes...)
	return res, nil
}

func evmAppendSignature(
	evmChainID *big.Int,
	unsignedTx []byte,
	tssSig tss.KeysignResponse,
) (*gtypes.Transaction, error) {
	txData, err := reth.DecodeUnsignedPayload(unsignedTx)
	if err != nil {
		return nil, fmt.Errorf("reth.DecodeUnsignedPayload: %v", err)
	}

	var sig []byte
	sig = append(sig, gcommon.FromHex(tssSig.R)...)
	sig = append(sig, gcommon.FromHex(tssSig.S)...)
	sig = append(sig, gcommon.FromHex(tssSig.RecoveryID)...)

	tx, err := gtypes.NewTx(txData).WithSignature(gtypes.NewPragueSigner(evmChainID), sig)
	if err != nil {
		return nil, fmt.Errorf("gtypes.NewTx(txData).WithSignature: %v", err)
	}
	return tx, nil
}

func (p *PayrollPlugin) evmEstimateTx(
	ctx context.Context,
	from, to gcommon.Address,
	value *big.Int,
	data []byte,
) (uint64, uint64, *big.Int, *big.Int, gtypes.AccessList, error) {
	var eg errgroup.Group
	var gasLimit uint64
	eg.Go(func() error {
		r, e := p.rpcClient.EstimateGas(ctx, ethereum.CallMsg{
			From:  from,
			To:    &to,
			Data:  data,
			Value: value,
		})
		if e != nil {
			return fmt.Errorf("p.rpcClient.EstimateGas: %v", e)
		}
		gasLimit = r
		return nil
	})

	var gasTipCap *big.Int
	eg.Go(func() error {
		r, e := p.rpcClient.SuggestGasTipCap(ctx)
		if e != nil {
			return fmt.Errorf("p.rpcClient.SuggestGasTipCap: %v", e)
		}
		gasTipCap = r
		return nil
	})

	var baseFee *big.Int
	eg.Go(func() error {
		feeHistory, e := p.rpcClient.FeeHistory(ctx, 1, nil, nil)
		if e != nil {
			return fmt.Errorf("p.rpcClient.FeeHistory: %v", e)
		}
		if len(feeHistory.BaseFee) == 0 {
			return fmt.Errorf("feeHistory.BaseFee is empty")
		}
		baseFee = feeHistory.BaseFee[0]
		return nil
	})

	var nonce uint64
	eg.Go(func() error {
		r, e := p.nonceManager.GetNextNonce(from.Hex())
		if e != nil {
			return fmt.Errorf("p.nonceManager.GetNextNonce: %v", e)
		}
		nonce = r
		return nil
	})
	err := eg.Wait()
	if err != nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("eg.Wait: %v", err)
	}

	maxFeePerGas := new(big.Int).Add(gasTipCap, baseFee)

	type createAccessListArgs struct {
		From                 string `json:"from,omitempty"`
		To                   string `json:"to,omitempty"`
		Gas                  string `json:"gas,omitempty"`
		GasPrice             string `json:"gasPrice,omitempty"`
		MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas,omitempty"`
		MaxFeePerGas         string `json:"maxFeePerGas,omitempty"`
		Value                string `json:"value,omitempty"`
		Data                 string `json:"data,omitempty"`
	}
	createAccessListRes := struct {
		AccessList gtypes.AccessList `json:"accessList"`
		GasUsed    string            `json:"gasUsed"`
	}{}
	err = p.rpcClient.Client().CallContext(
		ctx,
		&createAccessListRes,
		"eth_createAccessList",
		[]interface{}{
			createAccessListArgs{
				From:                 from.Hex(),
				To:                   to.Hex(),
				Gas:                  "0x" + strconv.FormatUint(gasLimit, 16),
				MaxPriorityFeePerGas: "0x" + gcommon.Bytes2Hex(gasTipCap.Bytes()),
				MaxFeePerGas:         "0x" + gcommon.Bytes2Hex(maxFeePerGas.Bytes()),
				Value:                "0x" + gcommon.Bytes2Hex(value.Bytes()),
				Data:                 "0x" + gcommon.Bytes2Hex(data),
			},
			"latest",
		},
	)
	if err != nil {
		return 0, 0, nil, nil, nil, fmt.Errorf("p.rpcClient.Client().CallContext: %v", err)
	}

	return nonce, gasLimit, gasTipCap, maxFeePerGas, createAccessListRes.AccessList, nil
}

func (p *PayrollPlugin) evmMakeUnsignedTransfer(
	ctx context.Context,
	evmChainID *big.Int,
	senderPublicKey, tokenIDStr, amountStr, toStr string,
) ([]byte, error) {
	amount, ok := new(big.Int).SetString(amountStr, 10)
	if !ok {
		return nil, fmt.Errorf("new(big.Int).SetString: %s", amountStr)
	}

	to := gcommon.HexToAddress(toStr)
	tokenID := gcommon.HexToAddress(tokenIDStr)

	var (
		value *big.Int
		data  []byte
	)
	if tokenID == evmZeroAddress {
		value = amount
		data = nil
	} else {
		parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
		if err != nil {
			return nil, fmt.Errorf("abi.JSON(strings.NewReader(erc20ABI)): %v", err)
		}

		d, err := parsedABI.Pack("transfer", to, amount)
		if err != nil {
			return nil, fmt.Errorf("parsedABI.Pack: %v", err)
		}
		value = big.NewInt(0)
		data = d
	}

	senderAddressHex, err := address.GetEVMAddress(senderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("address.GetEVMAddress: %v", err)
	}

	nonce, gasLimit, gasTipCap, maxFeePerGas, accessList, err := p.evmEstimateTx(
		ctx,
		gcommon.HexToAddress(senderAddressHex),
		tokenID,
		value,
		data,
	)
	if err != nil {
		return nil, fmt.Errorf("p.evmEstimateTx: %v", err)
	}

	bytes, err := evmEncodeUnsignedDynamicFeeTx(
		evmChainID,
		nonce,
		tokenID,
		gasTipCap,
		maxFeePerGas,
		gasLimit,
		value,
		data,
		accessList,
	)
	if err != nil {
		return nil, fmt.Errorf("evmEncodeUnsignedDynamicFeeTx: %v", err)
	}
	return bytes, nil
}
