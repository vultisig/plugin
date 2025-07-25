package copytrader

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/internal/keysign"
	"github.com/vultisig/plugin/storage"
)

var _ plugin.Plugin = (*Plugin)(nil)

type Plugin struct {
	db                    storage.DatabaseStorage
	signer                *keysign.Signer
	eth                   *evm.SDK
	ethRpc                *ethclient.Client
	logger                logrus.FieldLogger
	txIndexerService      *tx_indexer.Service
	client                *asynq.Client
	vaultStorage          vault.Storage
	vaultEncryptionSecret string
	blockID               uint64
}

func NewPlugin(
	db storage.DatabaseStorage,
	signer *keysign.Signer,
	vaultStorage vault.Storage,
	ethRpc *ethclient.Client,
	txIndexerService *tx_indexer.Service,
	client *asynq.Client,
	vaultEncryptionSecret string,
) (*Plugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	var (
		eth          *evm.SDK
		currentBlock uint64
	)
	if ethRpc != nil {
		ethEvmChainID, err := common.Ethereum.EvmID()
		if err != nil {
			return nil, fmt.Errorf("failed to get Ethereum EVM ID: %w", err)
		}
		eth = evm.NewSDK(ethEvmChainID, ethRpc, ethRpc.Client())

		currentBlock, err = ethRpc.BlockNumber(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get block: %w", err)
		}
	}

	return &Plugin{
		db:                    db,
		signer:                signer,
		eth:                   eth,
		ethRpc:                ethRpc,
		logger:                logrus.WithField("plugin", "copytrader"),
		txIndexerService:      txIndexerService,
		client:                client,
		vaultStorage:          vaultStorage,
		vaultEncryptionSecret: vaultEncryptionSecret,
		blockID:               currentBlock,
	}, nil
}
