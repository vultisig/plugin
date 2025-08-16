package fees

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/plugin/common"
	rcommon "github.com/vultisig/recipes/common"
	"github.com/vultisig/recipes/engine"
	reth "github.com/vultisig/recipes/ethereum"
	resolver "github.com/vultisig/recipes/resolver"

	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	vtypes "github.com/vultisig/verifier/types"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/vultisig/plugin/internal/types"
)

func (fp *FeePlugin) proposeTransactions(ctx context.Context, policy vtypes.PluginPolicy, run types.FeeRun) ([]vtypes.PluginKeysignRequest, error) {

	if policy.ID != run.PolicyID {
		return nil, fmt.Errorf("policy id does not match run policy id")
	}

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
	ethAddress, _, _, err := address.GetAddress(vault.PublicKeyEcdsa, vault.HexChainCode, vcommon.Ethereum)
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

	amount := run.TotalAmount

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
					Chain:        vcommon.Ethereum,
					Hash:         base64.StdEncoding.EncodeToString(msgHash[:]),
					HashFunction: vtypes.HashFunction_SHA256,
				},
			},
			SessionID:        "",
			HexEncryptionKey: "",
			PolicyID:         policy.ID,
			PluginID:         policy.PluginID.String(),
		},
		Transaction: txHex,
	}

	txs = append(txs, signRequest)

	return txs, nil
}

// deprecated, use proposeTransactions instead as it relies on a fee run and a context
func (fp *FeePlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	return nil, errors.New("not implemented")
}

func (fp *FeePlugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
	runId uuid.UUID,
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

	txBytes, txErr := hexutilDecode(req.Transaction)
	r, rErr := hexutilDecode(sig.R)
	s, sErr := hexutilDecode(sig.S)
	v, vErr := hexutilDecode(sig.RecoveryID)
	if txErr != nil || rErr != nil || sErr != nil || vErr != nil {
		return fmt.Errorf("error decoding tx or sigs: %w", errors.Join(txErr, rErr, sErr, vErr))
	}

	txHash, err := getHash(txBytes, r, s, v, fp.config.ChainId)
	if err != nil {
		return fmt.Errorf("failed to get hash: %w", err)
	}

	erc20tx, err := decodeTx(req.Transaction)
	if err != nil {
		fp.logger.WithError(err).Error("failed to decode tx")
		return fmt.Errorf("failed to decode tx: %w", err)
	}

	fp.logger.WithFields(logrus.Fields{
		"tx_hash":    txHash.Hash().Hex(),
		"tx_to":      erc20tx.to.Hex(),
		"tx_amount":  erc20tx.amount.String(),
		"tx_token":   erc20tx.token.Hex(),
		"public_key": pluginPolicy.PublicKey,
	}).Info("fee collection transaction")

	tx, err := fp.eth.Send(ctx, txBytes, r, s, v)
	if err != nil {
		fp.logger.WithError(err).WithField("tx_hex", req.Transaction).Error("fp.eth.Send")
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	// This is exceptionally important, as if it errors, the transaction will internally be recorded as draft, even after it's been broadcasted
	if err := fp.db.SetFeeRunSent(ctx, runId, tx.Hash().Hex()); err != nil { //TODO pass the real tx id
		return fmt.Errorf("failed to set fee run sent: %w", err)
	}

	// Log successful transaction broadcast
	fp.logger.WithField("hash", tx.Hash().Hex()).Info("fee collection transaction successfully broadcasted")
	return nil

}

func (fp *FeePlugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
	// First validate the plugin policy itself
	err := fp.ValidatePluginPolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	// Get the recipe from the policy for transaction validation
	recipe, err := policy.GetRecipe()
	if err != nil {
		return fmt.Errorf("failed to get recipe from policy: %v", err)
	}

	// Create a recipe engine for evaluating transactions
	eng := engine.NewEngine()

	// Validate each proposed transaction
	for _, tx := range txs {
		for _, keysignMessage := range tx.Messages {
			txBytes, err := base64.StdEncoding.DecodeString(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to decode transaction: %w", err)
			}

			// Evaluate if the transaction is allowed by the policy
			_, err = eng.Evaluate(recipe, rcommon.Chain(keysignMessage.Chain), txBytes)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}
		}
	}

	return nil
}

// deprecated, no longer part of the flow. initSign handles the transaction signing, sending and recording of initial state. The process thereafter is handled by the post_tx flow
func (fp *FeePlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	return fmt.Errorf("not implemented")
}
