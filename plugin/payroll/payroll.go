package payroll

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/plugin/common"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/vault"
)

var _ common.Plugin = (*PayrollPlugin)(nil)

type PayrollPlugin struct {
	db               storage.DatabaseStorage
	eth              *evm.SDK
	logger           logrus.FieldLogger
	config           *PluginConfig
	txIndexerService *tx_indexer.Service
	client           *asynq.Client
	inspector        *asynq.Inspector
	vaultStorage     vault.Storage
	encryptionSecret string
}

func NewPayrollPlugin(
	db storage.DatabaseStorage,
	vaultStorage vault.Storage,
	baseConfigPath string,
	txIndexerService *tx_indexer.Service,
	client *asynq.Client,
	inspector *asynq.Inspector,
	encryptionSecret string,
) (*PayrollPlugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}
	cfg, err := loadPluginConfig(baseConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin config: %w", err)
	}

	rpcClient, err := ethclient.Dial(cfg.RpcURL)
	if err != nil {
		return nil, err
	}

	ethEvmChainID, err := vcommon.Ethereum.EvmID()
	if err != nil {
		return nil, fmt.Errorf("common.Ethereum.EvmID: %w", err)
	}

	return &PayrollPlugin{
		db:               db,
		eth:              evm.NewSDK(ethEvmChainID, rpcClient, rpcClient.Client()),
		logger:           logrus.WithField("plugin", "payroll"),
		config:           cfg,
		txIndexerService: txIndexerService,
		client:           client,
		inspector:        inspector,
		vaultStorage:     vaultStorage,
		encryptionSecret: encryptionSecret,
	}, nil
}
