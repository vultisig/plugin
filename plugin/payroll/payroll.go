package payroll

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"

	"github.com/vultisig/plugin/storage"
)

type PayrollPlugin struct {
	db           storage.DatabaseStorage
	nonceManager *NonceManager
	rpcClient    *ethclient.Client
	logger       logrus.FieldLogger
	config       *PluginConfig
}

func NewPayrollPlugin(db storage.DatabaseStorage, logger logrus.FieldLogger, baseConfigPath string) (*PayrollPlugin, error) {
	cfg, err := loadPluginConfig(baseConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin config: %w", err)
	}

	rpcClient, err := ethclient.Dial(cfg.RpcURL)
	if err != nil {
		return nil, err
	}

	return &PayrollPlugin{
		db:           db,
		rpcClient:    rpcClient,
		nonceManager: NewNonceManager(rpcClient),
		logger:       logger,
		config:       cfg,
	}, nil
}

func (p *PayrollPlugin) GetNextNonce(address string) (uint64, error) {
	return p.nonceManager.GetNextNonce(address)
}
