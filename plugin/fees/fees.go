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
	"github.com/vultisig/verifier/plugin"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault_config"

	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/plugin/storage"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/vault"
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
	BaseConfigPath string                          `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis          storage.RedisConfig             `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage   vault_config.BlockStorageConfig `mapstructure:"block_storage" json:"block_storage,omitempty"`
	Datadog        struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

var _ plugin.Plugin = (*FeePlugin)(nil)

type FeePlugin struct {
	vaultService *vault.ManagementService
	db           storage.DatabaseStorage
	rpcClient    *ethclient.Client
	logger       logrus.FieldLogger
	verifierApi  *verifierapi.VerifierApi
	config       *FeeConfig
}

// TODO garry, this needs work
func NewFeePlugin(db storage.DatabaseStorage, logger logrus.FieldLogger, baseConfigPath string, feeConfig *FeeConfig) (*FeePlugin, error) {
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

	verifierApi := verifierapi.NewVerifierApi(feeConfig.VerifierUrl, logger.(*logrus.Logger))
	if verifierApi == nil {
		return nil, fmt.Errorf("failed to create verifier api")
	}

	return &FeePlugin{
		db:          db,
		rpcClient:   rpcClient,
		logger:      logger.WithField("plugin", "fees"),
		config:      feeConfig,
		verifierApi: verifierApi,
	}, nil
}

func (fp FeePlugin) GetRecipeSpecification() rtypes.RecipeSchema {
	fp.logger.Debug("Getting recipe specification")
	//TODO garry
	return rtypes.RecipeSchema{
		PluginId: "vultisig-fees-fees",
		Version:  1,
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
func (fp *FeePlugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	return []vtypes.PluginKeysignRequest{}, nil
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
	case FeeCollectionTypeByPolicy:
		fp.Log(logrus.InfoLevel, "Collecting fees by policy")
		return fp.collectFeesByPolicy(feeCollectionFormat.Value)
	case FeeCollectionTypeByPluginID:
		fp.Log(logrus.InfoLevel, "Collecting fees by plugin id")
	case FeeCollectionTypeAll:
		fp.Log(logrus.InfoLevel, "Collecting fees by all")
	default:
		fp.Log(logrus.ErrorLevel, "Invalid fee collection type")
		return fmt.Errorf("invalid fee collection type")
	}

	return nil
}

// SWITCHED LOGIC TO HANDLE DIFFERENT FEE COLLECTION TYPES. These functions should be called by the public function "HandleFeeCollections"

// Collects fee data by ... Should only be called by HandleFeeCollections
func (fp *FeePlugin) collectFeesByPublicKey(publicKey string) error {
	return nil
}

// Collects fee data by ... Should only be called by HandleFeeCollections
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

		fp.Log(logrus.InfoLevel, "Fees to collect: ", feesToCollect)

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
func (fp *FeePlugin) collectFeesByAll() error {
	// TODO: implement logic
	return nil
}
