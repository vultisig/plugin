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
	"github.com/vultisig/plugin/common"
	rtypes "github.com/vultisig/recipes/types"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault_config"

	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
	plugincommon "github.com/vultisig/plugin/plugin/common"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/verifier/vault"
)

/*
All key logic related to fees will go here, that includes
- proposing a fee transaction
- getting fee information
*/

// TODO do we actually need this?
type BaseConfig struct {
	Server   common.ServerConfig `mapstructure:"server" json:"server"`
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
	vaultService     *vault.ManagementService //TODO garry - not sure if this is needed yet. For now a null pointer
	vaultStorage     *vault.BlockStorageImp
	db               storage.DatabaseStorage
	rpcClient        *ethclient.Client
	logger           logrus.FieldLogger
	verifierApi      *verifierapi.VerifierApi
	config           *FeeConfig
	txIndexerService *tx_indexer.Service
	nonceManager     *plugincommon.NonceManager
}

// TODO garry, this needs work
func NewFeePlugin(db storage.DatabaseStorage, logger logrus.FieldLogger, baseConfigPath string, vaultStorage *vault.BlockStorageImp, txIndexerService *tx_indexer.Service, feeConfig *FeeConfig) (*FeePlugin, error) {
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
					}
				},
				Required: true,
			},
		},
		Scheduling: &rtypes.SchedulingCapability{
			SupportsScheduling: true,
			SupportedFrequencies: []rtypes.ScheduleFrequency{
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY,
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY,
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_BIWEEKLY,
				rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY,
			},
			MaxScheduledExecutions: 100, //TODO garry - don't know if this is a good number or not
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}

// This wraps the logger with the plugin name and context "i.e the worker execution".
func (fp *FeePlugin) Log(level logrus.Level, args ...interface{}) {
	fp.logger.WithFields(logrus.Fields{
		"plugin":  "fees",
		"context": "execution",
	}).Log(level, args...)
}

func (fp *FeePlugin) GetPolicyFees(cfg BaseConfig) error {
	return nil
}

// TODO garry all
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
	fp.Log(logrus.InfoLevel, "Starting Fee Collection Job")

	// Figure out if we're collecting fees by public key, policy, or plugin id
	feeCollectionFormat := FeeCollectionFormat{
		FeeCollectionType: FeeCollectionTypeAll,
	}
	if len(task.Payload()) != 0 {
		if err := json.Unmarshal(task.Payload(), &feeCollectionFormat); err != nil {
			fp.Log(logrus.ErrorLevel, "Failed to unmarshal fee collection config")
			return err
		}
	}

	switch feeCollectionFormat.FeeCollectionType {
	case FeeCollectionTypeByPublicKey:
		fp.Log(logrus.InfoLevel, "Collecting fees by public key")
		return fp.collectFeesByPublicKey(feeCollectionFormat.Value)
	case FeeCollectionTypeByPolicy:
		fp.Log(logrus.InfoLevel, "Collecting fees by policy")
		return fp.collectFeesByPolicy(feeCollectionFormat.Value)
	case FeeCollectionTypeByPluginID:
		fp.Log(logrus.InfoLevel, "Collecting fees by plugin id")
	case FeeCollectionTypeAll:
		fp.Log(logrus.InfoLevel, "Collecting fees by all")
		return fp.collectAllFees()
	default:
		fp.Log(logrus.ErrorLevel, "Invalid fee collection type")
		return fmt.Errorf("invalid fee collection type")
	}

	return nil
}

// SWITCHED LOGIC TO HANDLE DIFFERENT FEE COLLECTION TYPES. These functions should be called by the public function "HandleFeeCollections"

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectFeesByPublicKey(publicKey string) error {
	// TODO: implement logic
	fp.Log(logrus.DebugLevel, "Collecting fees by policy: ")
	feesResponse, err := fp.verifierApi.GetPublicKeysFees(publicKey)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	fp.logger.Debug("Fees response: ", feesResponse)

	if feesResponse.FeesPendingCollection > 0 {
		fp.Log(logrus.InfoLevel, "Fees pending collection: ", feesResponse.FeesPendingCollection)

		feesToCollect := []uuid.UUID{}
		checkAmount := 0
		for _, fee := range feesResponse.Fees {
			fp.Log(logrus.DebugLevel, "Fee: ", fee)
			if !fee.Collected {
				feesToCollect = append(feesToCollect, fee.ID)
				checkAmount += fee.Amount
			}
		}
		if checkAmount != feesResponse.FeesPendingCollection {
			fp.Log(logrus.ErrorLevel, "Fees pending collection amount does not match the sum of the fees")
			return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
		}

		fp.Log(logrus.InfoLevel, "Fees to collect: ", feesToCollect)

	} else {
		fp.Log(logrus.InfoLevel, "No fees pending collection")
	}

	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
// Not yet working
func (fp *FeePlugin) collectFeesByPolicy(policyIdString string) error {
	// TODO: implement logic
	fp.Log(logrus.DebugLevel, "Collecting fees by policy: ")
	policyId, err := uuid.Parse(policyIdString)
	if err != nil {
		return fmt.Errorf("failed to parse policy id: %w", err)
	}
	feesResponse, err := fp.verifierApi.GetPluginPolicyFees(policyId)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	fp.logger.Debug("Fees response: ", feesResponse)

	if feesResponse.FeesPendingCollection > 0 {
		fp.Log(logrus.InfoLevel, "Fees pending collection: ", feesResponse.FeesPendingCollection)

		feesToCollect := []uuid.UUID{}
		checkAmount := 0
		for _, fee := range feesResponse.Fees {
			fp.Log(logrus.DebugLevel, "Fee: ", fee)
			if !fee.Collected {
				feesToCollect = append(feesToCollect, fee.ID)
				checkAmount += fee.Amount
			}
		}
		if checkAmount != feesResponse.FeesPendingCollection {
			fp.Log(logrus.ErrorLevel, "Fees pending collection amount does not match the sum of the fees")
			return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
		}

		// fp.buildUSDCEthFeeTransaction(feesToCollect)

		// fp.Log(logrus.InfoLevel, "Fees to collect: ", feesToCollect)

	} else {
		fp.Log(logrus.InfoLevel, "No fees pending collection")
	}

	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectFeesByPluginID(pluginId string) error {
	// TODO: implement logic
	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectAllFees() error {
	ctx := context.Background()
	fp.Log(logrus.DebugLevel, "Collecting all fees")
	feesResponse, err := fp.verifierApi.GetAllPublicKeysFees()
	if err != nil {
		fp.Log(logrus.ErrorLevel, "Failed to get plugin policy fees: ", err)
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	fp.logger.Debug("Fees response: ", feesResponse)

	for publicKey, feeHistory := range feesResponse {
		//TODO just for testing

		feePolicies, err := fp.db.GetAllPluginPolicies(ctx, publicKey, vtypes.PluginVultisigFees_feee)

		fp.Log(logrus.DebugLevel, "Public key: ", publicKey)
		fp.Log(logrus.DebugLevel, "Fee history: ", feeHistory)

		if feeHistory.FeesPendingCollection > 0 {
			fp.Log(logrus.InfoLevel, "Fees pending collection: ", feeHistory.FeesPendingCollection)

			feesToCollect := []uuid.UUID{}
			checkAmount := 0
			for _, fee := range feeHistory.Fees {
				fp.Log(logrus.DebugLevel, "Fee: ", fee)
				if !fee.Collected {
					feesToCollect = append(feesToCollect, fee.ID)
					checkAmount += fee.Amount
				}
			}
			if checkAmount != feeHistory.FeesPendingCollection {
				fp.Log(logrus.ErrorLevel, "Fees pending collection amount does not match the sum of the fees")
				return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
			}

			fp.executeFeeCollection(publicKey, feesToCollect)

		} else {
			fp.Log(logrus.InfoLevel, "No fees pending collection for public key: ", publicKey)
		}
	}

	return nil
}

func (fp *FeePlugin) executeFeeCollection(ecdsaPublicKey string, feeIds []verifierapi.FeeDto) error {

	ctx := context.Background()
	fp.Log(logrus.DebugLevel, "Executing fee collection for public key: ", ecdsaPublicKey)

	//Get fee policy document
	feePolicies, err := fp.db.GetAllPluginPolicies(ctx, ecdsaPublicKey, vtypes.PluginVultisigFees_feee, true)
	if err != nil {
		fp.Log(logrus.DebugLevel, "Failed to get fee policies: ", err)
		return fmt.Errorf("failed to get fee policies: %w", err)
	}
	if len(feePolicies) == 0 {
		fp.Log(logrus.DebugLevel, "No fee policies found")
		return fmt.Errorf("no fee policies found")
	} else if len(feePolicies) > 1 {
		fp.Log(logrus.DebugLevel, "Multiple fee policies found")
		return fmt.Errorf("multiple fee policies found")
	}
	feePolicy := feePolicies[0]
	fp.Log(logrus.DebugLevel, "Fee policy: ", feePolicy)

	//Here we check if the fee collection is already in progress for the public key.
	feeRun, err := fp.db.CreateFeeRun(ctx, feePolicy.ID, types.FeeRunStateDraft, feeIds)
	if err != nil {
		fp.Log(logrus.DebugLevel, "Failed to create fee run: ", err)
		return fmt.Errorf("failed to create fee run: %w", err)
	}
	fp.Log(logrus.DebugLevel, "Fee run created: ", feeRun)

	//Get vault and check it exists
	vaultFileName := vcommon.GetVaultBackupFilename(ecdsaPublicKey, PLUGIN_ID)
	vaultContent, err := fp.vaultStorage.GetVault(vaultFileName)
	if err != nil {
		// TODO some real error handling here
		fp.Log(logrus.DebugLevel, "Failed to get vault: ", err)
		return fmt.Errorf("failed to get vault", err)
	}
	if vaultContent == nil {
		// TODO some real error handling here
		fp.Log(logrus.DebugLevel, "Vault not found")
		return fmt.Errorf("vault not found")
	}

	keySignRequest, err := fp.ProposeTransactions(feePolicy)
	if err != nil {
		fp.Log(logrus.DebugLevel, "Failed to propose transactions: ", err)
	}
	fp.Log(logrus.DebugLevel, "Fee policy: ", feePolicy)

}
