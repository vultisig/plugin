package fees

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	rtypes "github.com/vultisig/recipes/types"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault_config"

	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
	plugincommon "github.com/vultisig/plugin/plugin/common"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/verifier/vault"
	"golang.org/x/sync/errgroup"
)

/*
All key logic related to fees will go here, that includes
- proposing a fee transaction
- getting fee information
*/

type BaseConfig struct {
	Server   api.ServerConfig `mapstructure:"server" json:"server"`
	Database struct {
		DSN string `mapstructure:"dsn" json:"dsn,omitempty"`
	} `mapstructure:"database" json:"database,omitempty"`
	BaseConfigPath string                    `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis          storage.RedisConfig       `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage   vault_config.BlockStorage `mapstructure:"block_storage" json:"block_storage,omitempty"`
	Datadog        struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

var _ plugin.Plugin = (*FeePlugin)(nil)

type FeePlugin struct {
	vaultService     *vault.ManagementService
	vaultStorage     *vault.BlockStorageImp
	db               storage.DatabaseStorage
	rpcClient        *ethclient.Client
	logger           logrus.FieldLogger
	verifierApi      *verifierapi.VerifierApi
	config           *FeeConfig
	txIndexerService *tx_indexer.Service
	nonceManager     *plugincommon.NonceManager
	asynqInspector   *asynq.Inspector
	asynqClient      *asynq.Client
	encryptionSecret string
}

func NewFeePlugin(db storage.DatabaseStorage, logger logrus.FieldLogger, baseConfigPath string, vaultStorage *vault.BlockStorageImp, txIndexerService *tx_indexer.Service, inspector *asynq.Inspector, client *asynq.Client, feeConfig *FeeConfig, encryptionSecret string) (*FeePlugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	rpcClient, err := ethclient.Dial(feeConfig.RpcURL)
	if err != nil {
		return nil, err
	}

	if _, ok := logger.(*logrus.Logger); !ok {
		return nil, fmt.Errorf("logger must be *logrus.Logger, got %T", logger)
	}

	if vaultStorage == nil {
		return nil, fmt.Errorf("vault storage cannot be nil")
	}

	verifierApi := verifierapi.NewVerifierApi(feeConfig.VerifierUrl, logger.(*logrus.Logger))
	if verifierApi == nil {
		return nil, fmt.Errorf("failed to create verifier api")
	}

	return &FeePlugin{
		db:               db,
		rpcClient:        rpcClient,
		logger:           logger.WithField("plugin", "fees"),
		config:           feeConfig,
		verifierApi:      verifierApi,
		vaultStorage:     vaultStorage,
		txIndexerService: txIndexerService,
		asynqInspector:   inspector,
		asynqClient:      client,
		nonceManager:     plugincommon.NewNonceManager(rpcClient),
		encryptionSecret: encryptionSecret,
	}, nil
}

func (fp FeePlugin) GetRecipeSpecification() rtypes.RecipeSchema {
	return rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		PluginId:        string(vtypes.PluginVultisigFees_feee.String()),
		PluginName:      "Fee Plugin",
		PluginVersion:   1,
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
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_UNSPECIFIED,
						},
						Required: true,
					},
				},
				Required: true,
			},
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}

func (fp *FeePlugin) GetPolicyFees(cfg BaseConfig) error {
	return nil
}

func (fp *FeePlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return nil
}
func (fp *FeePlugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
	return nil
}
func (fp *FeePlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest vtypes.PluginKeysignRequest, policy vtypes.PluginPolicy) error {
	return nil
}

// HANDLER FUNCTIONS

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
		return fp.collectFeesByPublicKey(feeCollectionFormat.Value)
	case FeeCollectionTypeByPolicy:
		fp.logger.Info("Collecting fees by policy")
		return fp.collectFeesByPolicy(feeCollectionFormat.Value)
	case FeeCollectionTypeByPluginID:
		fp.logger.Info("Collecting fees by plugin id")
	case FeeCollectionTypeAll:
		fp.logger.Info("Collecting fees by all")
		return fp.collectAllFees()
	default:
		return fmt.Errorf("invalid fee collection type")
	}

	return nil
}

// SWITCHED LOGIC TO HANDLE DIFFERENT FEE COLLECTION TYPES. These functions should be called by the public function "HandleFeeCollections"

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectFeesByPublicKey(publicKey string) error {
	feesResponse, err := fp.verifierApi.GetPublicKeysFees(publicKey)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	if feesResponse.FeesPendingCollection > 0 {
		fp.logger.Info("Fees pending collection: ", feesResponse.FeesPendingCollection)

		feesToCollect := []uuid.UUID{}
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

		fp.logger.Info("Fees to collect: ", feesToCollect)

	} else {
		fp.logger.Info("No fees pending collection")
	}

	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectFeesByPolicy(policyIdString string) error {

	policyId, err := uuid.Parse(policyIdString)
	if err != nil {
		return fmt.Errorf("failed to parse policy id: %w", err)
	}
	feesResponse, err := fp.verifierApi.GetPluginPolicyFees(policyId)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	if feesResponse.FeesPendingCollection > 0 {
		fp.logger.Info("Fees pending collection: ", feesResponse.FeesPendingCollection)

		feesToCollect := []uuid.UUID{}
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

	} else {
		fp.logger.Info("No fees pending collection")
	}

	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectAllFees() error {
	ctx := context.Background()
	feesResponse, err := fp.verifierApi.GetAllPublicKeysFees()
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	for publicKey, feeHistory := range feesResponse {
		//TODO just for testing

		if feeHistory.FeesPendingCollection > 0 {

			fp.logger.Info("Fees pending collection: ", feeHistory.FeesPendingCollection)

			checkAmount := 0
			for _, fee := range feeHistory.Fees {
				if !fee.Collected {
					checkAmount += fee.Amount
				}
			}
			if checkAmount != feeHistory.FeesPendingCollection {
				return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
			}

			fp.executeFeeCollection(ctx, publicKey, feeHistory.Fees)

		} else {
			fp.logger.Info("No fees pending collection for public key: ", publicKey)
		}
	}

	return nil
}

func (fp *FeePlugin) executeFeeCollection(ctx context.Context, ecdsaPublicKey string, feeIds []verifierapi.FeeDto) error {

	//Get fee policy document
	feePolicies, err := fp.db.GetAllPluginPolicies(ctx, ecdsaPublicKey, vtypes.PluginVultisigFees_feee, true)
	if err != nil {
		return fmt.Errorf("failed to get fee policies: %w", err)
	}
	if len(feePolicies) == 0 {
		return fmt.Errorf("no fee policies found")
	} else if len(feePolicies) > 1 {
		return fmt.Errorf("multiple fee policies found")
	}
	feePolicy := feePolicies[0]

	//Here we check if the fee collection is already in progress for the public key.
	feeRun, err := fp.db.CreateFeeRun(ctx, feePolicy.ID, types.FeeRunStateDraft, feeIds)
	if err != nil {
		return fmt.Errorf("failed to create fee run: %w", err)
	}
	fp.logger.Info("Fee run created: ", feeRun)

	//Get vault and check it exists

	vaultFileName := vcommon.GetVaultBackupFilename(ecdsaPublicKey, vtypes.PluginVultisigFees_feee.String())
	vaultContent, err := fp.vaultStorage.GetVault(vaultFileName)
	if err != nil {
		return fmt.Errorf("failed to get vault: %w", err)
	}
	if vaultContent == nil {
		return fmt.Errorf("vault not found")
	}

	keySignRequests, err := fp.ProposeTransactions(feePolicy)
	if err != nil {
		return fmt.Errorf("failed to propose transactions: %w", err)
	}

	var eg errgroup.Group
	for _, keySignRequest := range keySignRequests {
		req := keySignRequest
		eg.Go(func() error {
			return fp.initSign(ctx, req, feePolicy)
		})
	}
	err = eg.Wait()
	if err != nil {
		return fmt.Errorf("eg.Wait: %s, %w", err, asynq.SkipRetry)
	}

	return nil
}
