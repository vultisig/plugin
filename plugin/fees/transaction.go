package fees

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/plugin/common"
	"github.com/vultisig/recipes/chain"
	"github.com/vultisig/recipes/engine"
	reth "github.com/vultisig/recipes/ethereum"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	vtypes "github.com/vultisig/verifier/types"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
)

func (fp *FeePlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {

	// Set config, get encryption secret and then get the vault connected to the fee policy.
	ctx := context.Background()
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

	chain := vcommon.Ethereum
	txs := []vtypes.PluginKeysignRequest{}

	// This should only return one rule, but in case there are more/fewer rules, we'll loop through them all and error if it's the case.
	for _, rule := range recipe.Rules {

		// This section of code goes through the rules in the fee policy. It looks for the recipient of the fee collection policy and extracts it. If other data is found throws an error as they're unsupported rules.
		var recipient string // The address specified in the fee policy.
		switch rule.Resource {
		case "ethereum.usdc.transfer":
			for _, constraint := range rule.ParameterConstraints {
				if constraint.ParameterName == "recipient" {
					if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
						return nil, fmt.Errorf("recipient constraint is not a fixed value")
					}
				}
				fixedValue := constraint.Constraint.GetValue().(*rtypes.Constraint_FixedValue)
				recipient = fixedValue.FixedValue
			}
		default:
			return nil, fmt.Errorf("unsupported rule: %v", rule.Id)
		}
		if recipient == "" {
			return nil, fmt.Errorf("recipient is not set in policy")
		}

		// Here we call the verifier api to get a list of fees that have the same public key as the signed policy document.
		feeHistory, err := fp.verifierApi.GetPublicKeysFees(policy.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get fee history: %v", err)
		}
		amount := feeHistory.FeesPendingCollection

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

		txToTrack, e := fp.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
			PluginID:      policy.PluginID,
			PolicyID:      policy.ID,
			ChainID:       chain,
			TokenID:       usdc.Address,
			FromPublicKey: policy.PublicKey,
			ToPublicKey:   recipient,
			ProposedTxHex: txHex,
		})
		if e != nil {
			return nil, fmt.Errorf("error creating tx indexed transaction: %w", e)
		}

		msgHash := sha256.Sum256(txHashToSign.Bytes())

		signRequest := vtypes.PluginKeysignRequest{
			KeysignRequest: vtypes.KeysignRequest{
				PublicKey: policy.PublicKey,
				Messages: []vtypes.KeysignMessage{
					{
						TxIndexerID:  txToTrack.ID.String(),
						Message:      base64.StdEncoding.EncodeToString(txHashToSign.Bytes()),
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
	}

	return txs, nil
}

func (fp *FeePlugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
	runId uuid.UUID,
) error {

	if runId != uuid.Nil {
		if len(req.Messages) != 1 {
			return fmt.Errorf("multiple messages in key sign request, expected 1")
		}
		txId, err := uuid.Parse(req.Messages[0].TxIndexerID)
		if err != nil {
			return fmt.Errorf("failed to parse tx indexer id: %w", err)
		}
		err = fp.db.SetFeeRunSent(ctx, runId, txId)
		if err != nil {
			return fmt.Errorf("failed to update fee run: %w", err)
		}
	}

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

	err = fp.SigningComplete(ctx, sig, req, pluginPolicy)
	if err != nil {
		fp.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("failed to complete signing process: %w", err)
	}
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
			// Get the chain for the transaction
			messageChain, err := chain.GetChain(strings.ToLower(keysignMessage.Chain.String()))
			if err != nil {
				return fmt.Errorf("failed to get chain: %w", err)
			}

			// Parse the transaction to validate its structure
			decodedTx, err := messageChain.ParseTransaction(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to parse transaction: %w", err)
			}

			// Evaluate if the transaction is allowed by the policy
			transactionAllowed, _, err := eng.Evaluate(recipe, messageChain, decodedTx)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}

			if !transactionAllowed {
				return fmt.Errorf("transaction %s on %s not allowed by policy", keysignMessage.Hash, keysignMessage.Chain)
			}
		}
	}

	return nil
}

func (fp *FeePlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	// Broadcast the signed transaction to the Ethereum network
	tx, err := fp.eth.Send(
		ctx,
		gcommon.FromHex(signRequest.Transaction),
		gcommon.Hex2Bytes(signature.R),
		gcommon.Hex2Bytes(signature.S),
		gcommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		fp.logger.WithError(err).WithField("tx_hex", signRequest.Transaction).Error("fp.eth.Send")
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	// Log successful transaction broadcast
	fp.logger.WithField("hash", tx.Hash().Hex()).Info("fee collection transaction successfully broadcasted")
	return nil
}
