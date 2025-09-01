package fees

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"runtime/debug"
	"strconv"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	reth "github.com/vultisig/recipes/ethereum"
	"github.com/vultisig/recipes/resolver"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/vultisig-go/address"
	vgcommon "github.com/vultisig/vultisig-go/common"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/types"
)

/* ------------------------------------------------------------------------------------------------
HANDLING TRANSACTIONS
here we handle the transactions for a fee run
------------------------------------------------------------------------------------------------ */

func (fp *FeePlugin) HandleTransactions(ctx context.Context, task *asynq.Task) error {
	fp.logger.Info("Starting Fee Transaction Job. Acquiring mutex")
	fp.transactingMutex.Lock()
	fp.logger.Info("Mutex acquired")

	defer func() {
		fp.transactingMutex.Unlock()
		fp.logger.Info("Mutex released")
	}()

	fp.logger.Info("Getting all fee runs")
	feeBatches, err := fp.db.GetFeeBatchByStatus(ctx, types.FeeBatchStateDraft)
	if err != nil {
		fp.logger.WithError(err).Error("Failed to get fee runs")
		return fmt.Errorf("failed to get fee runs: %w", err)
	}

	sem := semaphore.NewWeighted(int64(fp.config.Jobs.Transact.MaxConcurrentJobs))
	var eg errgroup.Group

	for _, batch := range feeBatches {
		feeBatch := batch
		eg.Go(func() error {
			// Add panic recovery for this goroutine
			defer func() {
				if r := recover(); r != nil {
					fp.logger.WithFields(logrus.Fields{
						"public_key": feeBatch.PublicKey,
						"panic":      r,
					}).Error("Recovered from panic in fee transaction processing")
					debug.PrintStack()
				}
			}()

			fp.logger.WithFields(logrus.Fields{"public_key": feeBatch.PublicKey}).Info("Processing fee policy")

			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)

			policies, err := fp.db.GetPluginPolicies(ctx, feeBatch.PublicKey, vtypes.PluginVultisigFees_feee, true)
			if err != nil {
				fp.logger.WithError(err).WithFields(logrus.Fields{
					"public_key": feeBatch.PublicKey,
				}).Error("Failed to get plugin policy")
				return err
			}
			if len(policies) != 1 {
				fp.logger.WithFields(logrus.Fields{
					"public_key": feeBatch.PublicKey,
				}).Error(fmt.Sprintf("Expected 1 plugin policy, got %d", len(policies)))
				return fmt.Errorf("expected 1 plugin policy, got %d", len(policies))
			}

			policy := policies[0]

			if err := fp.executeFeeTransaction(ctx, feeBatch, policy); err != nil {
				fp.logger.WithError(err).WithFields(logrus.Fields{
					"public_key": feeBatch.PublicKey,
				}).Error("Failed to execute fee transaction")
				return err
			}
			return nil
		})
	}

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to execute fee transaction: %w", err)
	}

	return nil
}

func (fp *FeePlugin) executeFeeTransaction(ctx context.Context, feeBatch types.FeeBatch, feePolicy vtypes.PluginPolicy) error {

	fp.logger.WithFields(logrus.Fields{
		"amount":    feeBatch.Amount,
		"publicKey": feePolicy.PublicKey,
		"policyId":  feePolicy.ID,
		"batchId":   feeBatch.BatchID,
	}).Info("Executing fee transaction")

	// Get a vault and sign the transactions
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Getting vault")
	_, err := common.GetVaultFromPolicy(fp.vaultStorage, feePolicy, fp.encryptionSecret)
	if err != nil {
		return fmt.Errorf("failed to get vault: %w", err)
	}

	keySignRequests, err := fp.proposeTransactions(ctx, feePolicy, feeBatch, feeBatch.Amount)
	if err != nil {
		return fmt.Errorf("failed to propose transactions: %w", err)
	}
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Key sign requests proposed")
	for _, keySignRequest := range keySignRequests {
		req := keySignRequest
		if err := fp.initSign(ctx, req, feePolicy, feeBatch); err != nil {
			return fmt.Errorf("failed to init sign: %w", err)
		}
	}

	return nil
}

func (fp *FeePlugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
	feeBatch types.FeeBatch,
) error {

	sigs, err := fp.signer.Sign(ctx, req)
	if err != nil {
		fp.logger.WithError(err).Error("Keysign failed")
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	if len(sigs) != 1 {
		fp.logger.
			WithField("sigs_count", len(sigs)).
			Error("expected only 1 message+sig per request for evm")
		return fmt.Errorf("failed to sign transaction: invalid signature count: %d", len(sigs))
	}

	var sig tss.KeysignResponse
	for _, s := range sigs {
		sig = s
	}

	decodedHexTx, decodedHexTxErr := base64.StdEncoding.DecodeString(req.Transaction)
	if decodedHexTxErr != nil {
		return fmt.Errorf("failed to decode transaction: %w", decodedHexTxErr)
	}

	r, rErr := hexutilDecode(sig.R)
	s, sErr := hexutilDecode(sig.S)
	v, vErr := hexutilDecode(sig.RecoveryID)
	if rErr != nil || sErr != nil || vErr != nil {
		return fmt.Errorf("error decoding tx or sigs: %w", errors.Join(rErr, sErr, vErr))
	}

	txHash, err := getHash(decodedHexTx, r, s, v, fp.config.ChainId)
	if err != nil {
		return fmt.Errorf("failed to get hash: %w", err)
	}

	erc20tx, err := decodeTx(hexutil.Encode(decodedHexTx))
	if err != nil {
		fp.logger.WithError(err).Error("failed to decode tx")
		return fmt.Errorf("failed to decode tx: %w", err)
	}

	tx, err := fp.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	var rollbackErr error
	defer func() {
		if rollbackErr != nil {
			tx.Rollback(ctx)
		}
	}()

	if err := fp.db.SetFeeBatchSent(ctx, tx, txHash.Hash().Hex(), feeBatch.BatchID); err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to set fee batch sent: %w", err)
	}
	resp, err := fp.verifierApi.UpdateFeeBatch(pluginPolicy.PublicKey, feeBatch.BatchID, txHash.Hash().Hex(), types.FeeBatchStateSent)
	if err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to update fee batch: %w", err)
	}
	if resp.Error.Message != "" {
		rollbackErr = err
		return fmt.Errorf("failed to update fee batch: %s", resp.Error.Message)
	}

	if err := tx.Commit(ctx); err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	fp.logger.WithFields(logrus.Fields{
		"tx_hash":    txHash.Hash().Hex(),
		"tx_to":      erc20tx.to.Hex(),
		"tx_amount":  erc20tx.amount.String(),
		"tx_token":   erc20tx.token.Hex(),
		"public_key": pluginPolicy.PublicKey,
		"batch_id":   feeBatch.BatchID,
	}).Info("fee collection transaction")

	ethTx, err := fp.eth.Send(ctx, decodedHexTx, r, s, v)
	if err != nil {
		fp.logger.WithError(err).WithField("tx_hex", req.Transaction).Error("fp.eth.Send")
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	fp.logger.WithFields(logrus.Fields{
		"tx_hash":    ethTx.Hash().Hex(),
		"tx_to":      erc20tx.to.Hex(),
		"tx_amount":  erc20tx.amount.String(),
		"tx_token":   erc20tx.token.Hex(),
		"public_key": pluginPolicy.PublicKey,
		"batch_id":   feeBatch.BatchID,
	}).Info("fee collection transaction successfully broadcasted")
	return nil

}

func (fp *FeePlugin) proposeTransactions(ctx context.Context, policy vtypes.PluginPolicy, feeBatch types.FeeBatch, amount uint64) ([]vtypes.PluginKeysignRequest, error) {

	vault, err := common.GetVaultFromPolicy(fp.vaultStorage, policy, fp.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from policy: %v", err)
	}

	// ERC20 USDC Token List
	var usdc *reth.Token = &reth.Token{
		ChainId:  1,
		Address:  fp.config.UsdcAddress,
		Name:     "USD Coin",
		Symbol:   "USDC",
		Decimals: 6,
	}

	// Get the ethereum derived addresses from the vaults master public key
	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vgcommon.Ethereum)
	if err != nil {
		return nil, fmt.Errorf("failed to get eth address: %v", err)
	}

	// Get some consts and types needed for later
	recipe, err := policy.GetRecipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get recipe from policy: %v", err)
	}

	txs := []vtypes.PluginKeysignRequest{}
	var magicConstantRecipientValue rtypes.MagicConstant = rtypes.MagicConstant_UNSPECIFIED

	// This should only return one rule, but in case there are more/fewer rules, we'll loop through them all and error if it's the case.
	if len(recipe.Rules) != 1 {
		return nil, fmt.Errorf("expected 1 rule, got %d", len(recipe.Rules))
	}
	rule := recipe.Rules[0]

	resourceName := "ethereum.erc20.transfer"
	if rule.Resource != resourceName {
		return nil, fmt.Errorf("rule resource expected to be %s", resourceName)
	}

	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "recipient" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT {
				return nil, fmt.Errorf("recipient constraint is not a magic constant")
			}
			iv, err := strconv.ParseInt(constraint.Constraint.GetFixedValue(), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse fixed value: %v", err)
			}
			magicConstantRecipientValue = rtypes.MagicConstant(iv)
		}
	}

	if magicConstantRecipientValue != rtypes.MagicConstant_VULTISIG_TREASURY {
		return nil, fmt.Errorf("recipient constraint is not a treasury magic constant")
	}

	treasuryResolver := resolver.NewDefaultTreasuryResolver()
	recipient, _, err := treasuryResolver.Resolve(magicConstantRecipientValue, "ethereum", "usdc")
	if err != nil {
		return nil, fmt.Errorf("failed to resolve treasury address: %v", err)
	}

	token := rule.Target.GetAddress()

	if gcommon.HexToAddress(token) != gcommon.HexToAddress(usdc.Address) {
		return nil, fmt.Errorf("token address does not match usdc address")
	}

	tx, err := fp.eth.MakeAnyTransfer(ctx,
		gcommon.HexToAddress(ethAddress),
		gcommon.HexToAddress(recipient),
		gcommon.HexToAddress(usdc.Address),
		big.NewInt(int64(amount)))
	if err != nil {
		return nil, fmt.Errorf("failed to generate unsigned transaction: %w", err)
	}

	txHex := hexutil.Encode(tx)

	txData, e := reth.DecodeUnsignedPayload(tx)
	if e != nil {
		return nil, fmt.Errorf("ethereum.DecodeUnsignedPayload: %w", e)
	}

	txHashToSign := etypes.LatestSignerForChainID(fp.config.ChainId).Hash(etypes.NewTx(txData))
	msgHash := sha256.Sum256(txHashToSign.Bytes())
	signRequest := vtypes.PluginKeysignRequest{
		KeysignRequest: vtypes.KeysignRequest{
			PublicKey: policy.PublicKey,
			Messages: []vtypes.KeysignMessage{
				{
					Message:      base64.StdEncoding.EncodeToString(txHashToSign.Bytes()),
					RawMessage:   txHex,
					Chain:        vgcommon.Ethereum,
					Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
					HashFunction: vtypes.HashFunction_SHA256,
					CustomData: map[string]interface{}{
						"batch_id": feeBatch.BatchID.String(),
					},
				},
			},
			PolicyID: policy.ID,
			PluginID: policy.PluginID.String(),
		},
		Transaction: base64.StdEncoding.EncodeToString(tx),
	}
	txs = append(txs, signRequest)

	return txs, nil
}
