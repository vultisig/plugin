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

func (p *PayrollPlugin) ProposeTransactions(
	ctx context.Context,
	policy vtypes.PluginPolicy,
) ([]vtypes.PluginKeysignRequest, error) {
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

			txHash, rawTx, e := p.generatePayrollTransaction(
				recipient.Amount,
				recipient.Address,
				payrollPolicy.ChainID[i],
				payrollPolicy.TokenID[i],
				policy.PublicKey,
				"",
				chain.GetDerivePath(),
			)
			if e != nil {
				return fmt.Errorf("p.generatePayrollTransaction: %w", e)
			}

			// Create signing request
			signRequest := vtypes.PluginKeysignRequest{
				KeysignRequest: vtypes.KeysignRequest{
					PublicKey: policy.PublicKey,
					Messages: []vtypes.KeysignMessage{
						{
							Message: hex.EncodeToString(rawTx),
							Hash:    hex.EncodeToString(txHash),
							Chain:   vcommon.Ethereum,
						},
					},
					SessionID:        uuid.New().String(),
					HexEncryptionKey: hexEncryptionKey,
					PolicyID:         policy.ID,
					PluginID:         policy.PluginID.String(),
				},
				Transaction: hex.EncodeToString(rawTx),
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

func (p *PayrollPlugin) generatePayrollTransaction(amountString, recipientString, evmChainID, tokenID, publicKey, chainCodeHex, derivePath string) ([]byte, []byte, error) {
	amount := new(big.Int)
	amount.SetString(amountString, 10)
	recipient := gcommon.HexToAddress(recipientString)

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse ABI: %v", err)
	}

	inputData, err := parsedABI.Pack("transfer", recipient, amount)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack transfer data: %v", err)
	}

	// create call message to estimate gas
	callMsg := ethereum.CallMsg{
		From:  recipient, // todo : this works, but maybe better to put the correct sender address once we have it
		To:    &recipient,
		Data:  inputData,
		Value: big.NewInt(0),
	}
	// estimate gas limit
	gasLimit, err := p.rpcClient.EstimateGas(context.Background(), callMsg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to estimate gas: %v", err)
	}
	// Use config values for gas calculations
	gasLimit = gasLimit * uint64(p.config.Gas.LimitMultiplier) / 100
	// get suggested gas price
	gasPrice, err := p.rpcClient.SuggestGasPrice(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get gas price: %v", err)
	}
	gasPrice = new(big.Int).Mul(gasPrice, big.NewInt(int64(p.config.Gas.PriceMultiplier)))
	// Parse chain ID
	chainIDInt := new(big.Int)
	chainIDInt.SetString(evmChainID, 10)
	fmt.Printf("Chain ID TEST 3: %s\n", chainIDInt.String())

	addressStr, _, _, err := address.GetAddress(publicKey, chainCodeHex, vcommon.Ethereum)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive address: %v", err)
	}

	derivedAddress := gcommon.HexToAddress(addressStr)

	nextNonce, err := p.GetNextNonce(derivedAddress.Hex())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get nonce: %v", err)
	}

	// Create unsigned transaction data
	V := new(big.Int).Set(chainIDInt)
	V = V.Mul(V, big.NewInt(2))
	V = V.Add(V, big.NewInt(35))
	txData := []interface{}{
		nextNonce,                     // nonce
		gasPrice,                      // gas price
		gasLimit,                      // gas limit
		gcommon.HexToAddress(tokenID), // to
		big.NewInt(0),                 // value
		inputData,                     // data
		V,                             // chain id
		uint(0),                       // empty v
		uint(0),                       // empty r
	}

	// Log each component separately
	p.logger.WithFields(logrus.Fields{
		"nonce":     txData[0],
		"gas_price": txData[1].(*big.Int).String(),
		"gas_limit": txData[2],
		"to":        txData[3].(gcommon.Address).Hex(),
		"value":     txData[4].(*big.Int).String(),
		"data_hex":  hex.EncodeToString(txData[5].([]byte)),
		"empty_v":   txData[6],
		"empty_r":   txData[7],
		"recipient": recipient.Hex(),
		"amount":    amount.String(),
	}).Info("Transaction components")

	rawTx, err := rlp.EncodeToBytes(txData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to RLP encode transaction: %v", err)
	}

	signer := gtypes.NewEIP155Signer(chainIDInt)
	tx := gtypes.NewTransaction(nextNonce, gcommon.HexToAddress(tokenID), big.NewInt(0), gasLimit, gasPrice, inputData)
	txHash := signer.Hash(tx).Bytes()

	p.logger.WithFields(logrus.Fields{
		"raw_tx_hex":   hex.EncodeToString(rawTx),
		"hash_to_sign": hex.EncodeToString(txHash),
	}).Info("Final transaction data")

	/*txBytes, err := hex.DecodeString(string(rawTx))
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return []types.PluginKeysignRequest{}, fmt.Errorf("failed to decode transaction hex: %w", err)
	}*/
	// unmarshal tx from sign req.transaction
	txCheck := &gtypes.Transaction{}
	err = rlp.DecodeBytes(rawTx, txCheck)
	if err != nil {
		p.logger.Errorf("Failed to RLP decode transaction: %v", err)
		return nil, nil, fmt.Errorf("failed to RLP decode transaction: %v: %w", err, asynq.SkipRetry)
	}
	fmt.Printf("Chain ID TEST 4: %s\n", txCheck.ChainId().String())

	return txHash, rawTx, nil
}

func (p *PayrollPlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	R, S, V, originalTx, chainID, _, err := p.convertData(signature, signRequest, policy)
	if err != nil {
		return fmt.Errorf("failed to convert R and S: %v", err)
	}

	innerTx := &gtypes.LegacyTx{
		Nonce:    originalTx.Nonce(),
		GasPrice: originalTx.GasPrice(),
		Gas:      originalTx.Gas(),
		To:       originalTx.To(),
		Value:    originalTx.Value(),
		Data:     originalTx.Data(),
		V:        V,
		R:        R,
		S:        S,
	}

	signedTx := gtypes.NewTx(innerTx)
	signer := gtypes.NewLondonSigner(chainID)
	sender, err := signer.Sender(signedTx)
	if err != nil {
		p.logger.WithError(err).Warn("Could not determine sender")
	} else {
		p.logger.WithField("sender", sender.Hex()).Info("Transaction sender")
	}

	// Check if RPC client is initialized
	if p.rpcClient == nil {
		return fmt.Errorf("RPC client not initialized")
	}

	err = p.rpcClient.SendTransaction(ctx, signedTx)
	if err != nil {
		p.logger.WithError(err).Error("Failed to broadcast transaction")
		return p.handleBroadcastError(err, sender)
	}

	p.logger.WithField("hash", signedTx.Hash().Hex()).Info("Transaction successfully broadcast")

	return p.monitorTransaction(signedTx)
}

func (p *PayrollPlugin) convertData(signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) (R *big.Int, S *big.Int, V *big.Int, originalTx *gtypes.Transaction, chainID *big.Int, recoveryID int64, err error) {
	// convert R and S from hex strings to big.Int
	R = new(big.Int)
	R.SetString(signature.R, 16)
	if R == nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse R value")
	}

	S = new(big.Int)
	S.SetString(signature.S, 16)
	if S == nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse S value")
	}

	// Decode the hex string to bytes first
	txBytes, err := hex.DecodeString(signRequest.Transaction)
	if err != nil {
		p.logger.Errorf("Failed to decode transaction hex: %v", err)
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to decode transaction hex: %w", err)
	}

	originalTx = new(gtypes.Transaction)
	if err := rlp.DecodeBytes(txBytes, originalTx); err != nil {
		p.logger.Errorf("Failed to unmarshal transaction: %v", err)
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	payrollPolicy := PayrollPolicy{}
	// TODO: convert the recipes to PayrollPolicy
	chainID = new(big.Int)
	chainID.SetString(payrollPolicy.ChainID[0], 10)

	/*chainID = originalTx.ChainId()
	fmt.Printf("Chain ID TEST: %s\n", chainID.String())*/

	// calculate V according to EIP-155
	recoveryID, err = strconv.ParseInt(signature.RecoveryID, 10, 64)
	if err != nil {
		return nil, nil, nil, nil, nil, 0, fmt.Errorf("failed to parse recovery ID: %w", err)
	}

	V = new(big.Int).Set(chainID)
	V.Mul(V, big.NewInt(2))
	V.Add(V, big.NewInt(35+recoveryID))

	return R, S, V, originalTx, chainID, recoveryID, nil
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
