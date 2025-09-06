package fees

import (
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/recipes/engine"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"
	vgcommon "github.com/vultisig/vultisig-go/common"

	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/plugin/storage"
)

/*
All key logic related to fees will go here, that includes
- proposing a fee transaction
- getting fee information
*/

var _ plugin.Spec = (*FeePlugin)(nil)

type FeePlugin struct {
	vaultStorage     *vault.BlockStorageImp
	signer           *keysign.Signer
	db               storage.DatabaseStorage
	eth              *evm.SDK
	logger           logrus.FieldLogger
	verifierApi      *verifierapi.VerifierApi
	config           *FeeConfig
	txIndexerService *tx_indexer.Service
	asynqInspector   *asynq.Inspector
	asynqClient      *asynq.Client
	encryptionSecret string
	transactingMutex sync.Mutex // when actual transactions are happening we cannot load fees
	ethClient        *ethclient.Client
}

// Suggest implements plugin.Spec.
func (fp *FeePlugin) Suggest(configuration map[string]any) (*rtypes.PolicySuggest, error) {
	return nil, fmt.Errorf("unimplemented")
}

func NewFeePlugin(db storage.DatabaseStorage,
	signer *keysign.Signer,
	logger logrus.FieldLogger,
	baseConfigPath string,
	vaultStorage *vault.BlockStorageImp,
	txIndexerService *tx_indexer.Service,
	inspector *asynq.Inspector,
	client *asynq.Client,
	feeConfig *FeeConfig,
	encryptionSecret string,
	verifierUrl string) (*FeePlugin, error) {

	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	rpcClient, err := ethclient.Dial(feeConfig.EthProvider)
	if err != nil {
		return nil, err
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
		feeConfig.VerifierToken,
		logger.(*logrus.Logger),
	)

	if verifierApi == nil {
		return nil, fmt.Errorf("failed to create verifier api")
	}

	return &FeePlugin{
		db:               db,
		eth:              evm.NewSDK(feeConfig.ChainId, rpcClient, rpcClient.Client()),
		signer:           signer,
		logger:           logger.WithField("plugin", "fees"),
		config:           feeConfig,
		verifierApi:      verifierApi,
		vaultStorage:     vaultStorage,
		txIndexerService: txIndexerService,
		asynqInspector:   inspector,
		asynqClient:      client,
		encryptionSecret: encryptionSecret,
		ethClient:        rpcClient,
	}, nil
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
			_, err = eng.Evaluate(recipe, vgcommon.Chain(keysignMessage.Chain), txBytes)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}
		}
	}

	return nil
}
