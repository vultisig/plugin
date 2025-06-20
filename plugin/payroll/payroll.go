package payroll

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
)

var _ plugin.Plugin = (*PayrollPlugin)(nil)

type PayrollPlugin struct {
	db               storage.DatabaseStorage
	nonceManager     *NonceManager
	rpcClient        *ethclient.Client
	logger           logrus.FieldLogger
	config           *PluginConfig
	txIndexerService *tx_indexer.Service
	client           *asynq.Client
	inspector        *asynq.Inspector
}

func NewPayrollPlugin(
	db storage.DatabaseStorage,
	baseConfigPath string,
	txIndexerService *tx_indexer.Service,
	client *asynq.Client,
	inspector *asynq.Inspector,
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

	return &PayrollPlugin{
		db:               db,
		rpcClient:        rpcClient,
		nonceManager:     NewNonceManager(rpcClient),
		logger:           logrus.WithField("plugin", "payroll"),
		config:           cfg,
		txIndexerService: txIndexerService,
		client:           client,
		inspector:        inspector,
	}, nil
}

func (p *PayrollPlugin) GetNextNonce(address string) (uint64, error) {
	return p.nonceManager.GetNextNonce(address)
}
