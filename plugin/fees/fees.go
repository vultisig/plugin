package fees

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"golang.org/x/sync/errgroup"

	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
)

/*
All key logic related to fees will go here, that includes
- proposing a fee transaction
- getting fee information
*/

var _ plugin.Plugin = (*FeePlugin)(nil)

type FeePlugin struct {
	vaultService     *vault.ManagementService
	vaultStorage     *vault.BlockStorageImp
	db               storage.DatabaseStorage
	eth              *evm.SDK
	logger           logrus.FieldLogger
	verifierApi      *verifierapi.VerifierApi
	config           *FeeConfig
	txIndexerService *tx_indexer.Service
	asynqInspector   *asynq.Inspector
	asynqClient      *asynq.Client
	encryptionSecret string
}

func NewFeePlugin(db storage.DatabaseStorage,
	logger logrus.FieldLogger,
	baseConfigPath string,
	vaultStorage *vault.BlockStorageImp,
	txIndexerService *tx_indexer.Service,
	inspector *asynq.Inspector,
	client *asynq.Client,
	feeConfig *FeeConfig,
	encryptionSecret string,
	verifierUrl, verifierToken string) (*FeePlugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	rpcClient, err := ethclient.Dial(feeConfig.RpcURL)
	if err != nil {
		return nil, err
	}

	// Initialize the Ethereum SDK for transaction broadcasting
	ethEvmChainID, err := vcommon.Ethereum.EvmID()
	if err != nil {
		return nil, fmt.Errorf("vcommon.Ethereum.EvmID: %w", err)
	}

	if _, ok := logger.(*logrus.Logger); !ok {
		return nil, fmt.Errorf("logger must be *logrus.Logger, got %T", logger)
	}

	if vaultStorage == nil {
		return nil, fmt.Errorf("vault storage cannot be nil")
	}

	if verifierUrl == "" {
		return nil, fmt.Errorf("verifier url cannot be empty")
	}

	verifierApi := verifierapi.NewVerifierApi(
		verifierUrl,
		verifierToken,
		logger.(*logrus.Logger),
	)
	if verifierApi == nil {
		return nil, fmt.Errorf("failed to create verifier api")
	}

	return &FeePlugin{
		db:               db,
		eth:              evm.NewSDK(ethEvmChainID, rpcClient, rpcClient.Client()),
		logger:           logger.WithField("plugin", "fees"),
		config:           feeConfig,
		verifierApi:      verifierApi,
		vaultStorage:     vaultStorage,
		txIndexerService: txIndexerService,
		asynqInspector:   inspector,
		asynqClient:      client,
		encryptionSecret: encryptionSecret,
	}, nil
}

/*
The handler of the asynq job. Fees can initialized and collected in 3 ways:
- By public key (queries the db for a single fee_policy and then kicks off the fee collection)
- By policy id (queries the db for a fee_policy matching that id and then kicks off the fee collection)
- All (queries the db for all fee_policies and then kicks off the fee collection for each policy)
*/
func (fp *FeePlugin) HandleCollections(ctx context.Context, task *asynq.Task) error {
	fp.logger.Info("Starting Fee Collection Job")

	// Figure out if we're collecting fees by public key, policy, or plugin id
	feeCollectionFormat := FeeCollectionFormat{
		FeeCollectionType: FeeCollectionTypeAll,
	}
	if len(task.Payload()) != 0 {
		if err := json.Unmarshal(task.Payload(), &feeCollectionFormat); err != nil {
			return fmt.Errorf("fp.HandleCollections, failed to unmarshall asynq task payload, %w", err)
		}
	}
	switch feeCollectionFormat.FeeCollectionType {
	case FeeCollectionTypeByPublicKey:
		fp.logger.Info("Collecting fees by public key")
		return fp.collectFeesByPublicKey(ctx, feeCollectionFormat.Value)
	case FeeCollectionTypeByPolicy:
		fp.logger.Info("Collecting fees by policy")
		return fp.collectFeesByPolicyId(ctx, feeCollectionFormat.Value)
	case FeeCollectionTypeAll:
		fp.logger.Info("Collecting all fees")
		return fp.collectAllFees(ctx)
	default:
		return fmt.Errorf("invalid fee collection type")
	}
}

func (fp *FeePlugin) collectFeesByPublicKey(ctx context.Context, publicKey string) error {
	// Get the fee policy from the database
	feePolicies, err := fp.db.GetAllPluginPolicies(ctx, publicKey, vtypes.PluginVultisigFees_feee, true)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy: %w", err)
	}
	if len(feePolicies) == 0 {
		return fmt.Errorf("no fee policy found for public key: %s", publicKey)
	}
	if len(feePolicies) > 1 {
		return fmt.Errorf("multiple fee policies found for public key: %s", publicKey)
	}
	return fp.executeFeeCollection(ctx, feePolicies[0])
}

func (fp *FeePlugin) collectFeesByPolicyId(ctx context.Context, policyId string) error {
	policyIdUuid, err := uuid.Parse(policyId)
	if err != nil {
		return fmt.Errorf("failed to parse policy id: %w", err)
	}
	policy, err := fp.db.GetPluginPolicy(ctx, policyIdUuid)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy: %w", err)
	}
	return fp.executeFeeCollection(ctx, *policy)
}

func (fp *FeePlugin) collectAllFees(ctx context.Context) error {
	fp.logger.Info("Collecting all fees")
	feePolicies, err := fp.db.GetAllPluginPolicies(ctx, "", vtypes.PluginVultisigFees_feee, true)
	if err != nil {
		return fmt.Errorf("failed to get fee policies: %w", err)
	}

	var eg errgroup.Group
	for _, feePolicy := range feePolicies {
		feePolicy := feePolicy // Capture by value
		eg.Go(func() error {
			return fp.executeFeeCollection(ctx, feePolicy)
		})
	}
	return eg.Wait()
}

/*
This function is the main function that collects fees. It is called by
- collectFeesByPublicKey,
- collectFeesByPolicyId
- collectAllFees
It does the following:
- Gets the list of fees from the verifier
- If there are fees to collect, it creates a fee run, errors if already being collected.
- It gets a vault and proposes the transactions
- It initializes the signing
*/
func (fp *FeePlugin) executeFeeCollection(ctx context.Context, feePolicy vtypes.PluginPolicy) error {

	// Get list of fees from the verifier connected to the fee policy
	feesResponse, err := fp.verifierApi.GetPublicKeysFees(feePolicy.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	// Early return if no fees to collect
	if feesResponse.FeesPendingCollection <= 0 {
		fp.logger.WithField("publicKey", feePolicy.PublicKey).Info("No fees pending collection")
		return nil
	}

	// If fees are greater than 0, we need to collect them
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Fees pending collection: ", feesResponse.FeesPendingCollection)

	// Get list of fee ids to be collected in this batch
	// Verify that the sum of the fees is equal to the fees pending collection
	feesToCollect := make([]uuid.UUID, 0, len(feesResponse.Fees))
	checkAmount := 0
	for _, fee := range feesResponse.Fees {
		if !fee.Collected {
			feesToCollect = append(feesToCollect, fee.ID)
			checkAmount += fee.Amount
		}
	}
	if checkAmount != feesResponse.FeesPendingCollection {
		return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
	}
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
		"amount":    checkAmount,
	}).Info("Collecting fee ids: ", feesToCollect)

	// Here we check if the fee collection is already in progress for any of the specific fee ids
	feeRun, err := fp.db.CreateFeeRun(ctx, feePolicy.ID, types.FeeRunStateDraft, feesResponse.Fees)
	if err != nil {
		return fmt.Errorf("failed to create fee run: %w", err)
	}
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Fee run created with id: ", feeRun.ID)

	// Get a vault and sign the transactions
	vaultFileName := vcommon.GetVaultBackupFilename(feePolicy.PublicKey, vtypes.PluginVultisigFees_feee.String())
	vaultContent, err := fp.vaultStorage.GetVault(vaultFileName)
	if err != nil {
		return fmt.Errorf("failed to get vault: %w", err)
	}
	if vaultContent == nil {
		return fmt.Errorf("vault not found")
	}

	// Propose the transactions
	keySignRequests, err := fp.ProposeTransactions(feePolicy)
	if err != nil {
		return fmt.Errorf("failed to propose transactions: %w", err)
	}

	for _, keySignRequest := range keySignRequests {
		req := keySignRequest
		if err := fp.initSign(ctx, req, feePolicy, feeRun.ID); err != nil {
			return fmt.Errorf("failed to init sign: %w", err)
		}
	}

	return nil
}
