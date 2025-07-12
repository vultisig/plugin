package payroll

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/keysign"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/vault"
)

var _ plugin.Plugin = (*PayrollPlugin)(nil)

type PayrollPlugin struct {
	db               storage.DatabaseStorage
	signer           *keysign.Signer
	eth              *evm.SDK
	logger           logrus.FieldLogger
	txIndexerService *tx_indexer.Service
	client           *asynq.Client
	vaultStorage     vault.Storage
	encryptionSecret string
}

func NewPayrollPlugin(
	db storage.DatabaseStorage,
	signer *keysign.Signer,
	vaultStorage vault.Storage,
	ethRpc *ethclient.Client,
	txIndexerService *tx_indexer.Service,
	client *asynq.Client,
	encryptionSecret string,
) (*PayrollPlugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	var eth *evm.SDK
	if ethRpc != nil {
		ethEvmChainID, err := common.Ethereum.EvmID()
		if err != nil {
			return nil, fmt.Errorf("common.Ethereum.EvmID: %w", err)
		}
		eth = evm.NewSDK(ethEvmChainID, ethRpc, ethRpc.Client())
	}

	return &PayrollPlugin{
		db:               db,
		signer:           signer,
		eth:              eth,
		logger:           logrus.WithField("plugin", "payroll"),
		txIndexerService: txIndexerService,
		client:           client,
		vaultStorage:     vaultStorage,
		encryptionSecret: encryptionSecret,
	}, nil
}
