package fees

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/plugin/common"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/tasks"
	plugincommon "github.com/vultisig/plugin/plugin/common"
	"github.com/vultisig/recipes/chain"
	reth "github.com/vultisig/recipes/ethereum"
	rtypes "github.com/vultisig/recipes/types"
	rutil "github.com/vultisig/recipes/util"
	"github.com/vultisig/verifier/address"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	vtypes "github.com/vultisig/verifier/types"
)

func (fp *FeePlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {

	// Set config, get encryption secret and then get the vault connected to the fee policy.
	ctx := context.Background()
	vault, err := common.GetVaultFromPolicy(fp.vaultStorage, policy, fp.encryptionSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from policy: %v", err)
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
	echain, err := chain.GetChain("ethereum")

	if err != nil {
		return nil, fmt.Errorf("failed to get ethereum chain: %v", err)
	}
	ethchain := echain.(*reth.Ethereum)
	chain := vcommon.Ethereum
	txs := []vtypes.PluginKeysignRequest{}

	// This should only return one rule, but in case there are more/fewer rules, we'll loop through them all and error if it's the case.
	for _, rule := range recipe.Rules {

		// This section of code goes through the rules in the fee policy. It looks for the recipient of the fee collection policy and extracts it. If other data is found throws an error as they're unsupported rules.
		var recipient string // The address specified in the fee policy.
		switch rule.Id {
		case "allow-usdc-transfer-to-collector":
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

		// This section of code is used to get the token address for the fee collection (just eth usdc for now)
		resourcePath, err := rutil.ParseResource(rule.Resource)
		if err != nil {
			return nil, fmt.Errorf("failed to parse resource: %v", err)
		}
		token, found := ethchain.GetToken(resourcePath.ProtocolId)
		if !found {
			return nil, fmt.Errorf("failed to get token: %v", resourcePath.ProtocolId)
		}

		// Here we call the verifier api to get a list of fees that have the same public key as the signed policy document.
		feeHistory, err := fp.verifierApi.GetPublicKeysFees(policy.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get fee history: %v", err)
		}
		amount := feeHistory.FeesPendingCollection

		//Check if fees have been collected withing a 6 hour time window.
		fromTime := time.Now().Add(-6 * time.Hour)
		toTime := time.Now()

		_, err = fp.txIndexerService.GetTxInTimeRange(
			ctx,
			chain,
			policy.PluginID,
			policy.ID,
			token.Address,
			recipient,
			fromTime,
			toTime,
		)
		if err == nil {
			fp.logger.WithFields(logrus.Fields{
				"recipient": recipient,
				"amount":    amount,
				"chain_id":  chain,
				"token_id":  token.Address,
			}).Info("transaction already proposed, skipping")
			return []vtypes.PluginKeysignRequest{}, nil
		}

		nonce, err := fp.nonceManager.GetNextNonce(ethAddress)
		if err != nil {
			return []vtypes.PluginKeysignRequest{}, fmt.Errorf("plugincommon.nonceManager.GetNextNonce: %w", err)
		}

		tx, e := plugincommon.GenUnsignedTx(
			ctx,
			chain,
			ethAddress,
			token.Address,
			fmt.Sprint(amount),
			recipient,
			fp.rpcClient,
			nonce,
		)

		if e != nil {
			return []vtypes.PluginKeysignRequest{}, fmt.Errorf("plugincommon.genUnsignedTx: %w", e)
		}

		txHex := hex.EncodeToString(tx)

		txToTrack, e := fp.txIndexerService.CreateTx(ctx, storage.CreateTxDto{
			PluginID:      policy.PluginID,
			PolicyID:      policy.ID,
			ChainID:       chain,
			TokenID:       token.Address,
			FromPublicKey: policy.PublicKey,
			ToPublicKey:   recipient,
			ProposedTxHex: txHex,
		})
		if e != nil {
			return []vtypes.PluginKeysignRequest{}, fmt.Errorf("fp.tx_indexer.CreateTx: %w", e)
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

// Copy from the payroll plugin. Checks if a tx was created
func (fp *FeePlugin) IsAlreadyProposed(
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

	_, err = fp.txIndexerService.GetTxInTimeRange(
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
	return false, fmt.Errorf("fp.txIndexerService.GetTxInTimeRange: %w", err)
}

func (fp *FeePlugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
) error {
	buf, e := json.Marshal(req)
	if e != nil {
		return fmt.Errorf("json.Marshal: %w", e)
	}

	task, e := fp.asynqClient.Enqueue(
		asynq.NewTask(tasks.TypeKeySignDKLS, buf),
		asynq.MaxRetry(0),
		asynq.Timeout(5*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME),
	)
	if e != nil {
		return fmt.Errorf("fp.client.Enqueue: %w", e)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
			taskInfo, er := fp.asynqInspector.GetTaskInfo(tasks.QUEUE_NAME, task.ID)
			if er != nil {
				return fmt.Errorf("fp.inspector.GetTaskInfo: %w", er)
			}
			if taskInfo.State != asynq.TaskStateCompleted {
				continue
			}
			if taskInfo.Result == nil {
				fp.logger.Info("taskInfo.Result is nil, skipping")
				return nil
			}

			var res map[string]tss.KeysignResponse
			er = json.Unmarshal(taskInfo.Result, &res)
			if er != nil {
				return fmt.Errorf("json.Unmarshal(taskInfo.Result, &res): %w", er)
			}

			var sig tss.KeysignResponse
			for _, v := range res { // one sig for evm (map with 1 key)
				sig = v
			}

			er = fp.SigningComplete(ctx, sig, req, pluginPolicy)
			if er != nil {
				return fmt.Errorf("fp.SigningComplete: %w", er)
			}

			fp.logger.WithField("public_key", req.PublicKey).
				Info("successfully signed and broadcasted")
			return nil
		}
	}
}
