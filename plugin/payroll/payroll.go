package payroll

import (
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
	"github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	"github.com/vultisig/verifier/vault"
)

var _ plugin.Spec = (*Plugin)(nil)

type Plugin struct {
	db                    storage.DatabaseStorage
	signer                *keysign.Signer
	eth                   *evm.SDK
	logger                logrus.FieldLogger
	txIndexerService      *tx_indexer.Service
	client                *asynq.Client
	vaultStorage          vault.Storage
	vaultEncryptionSecret string
}

// Suggest implements plugin.Spec.
func (p *Plugin) Suggest(configuration map[string]any) (*types.PolicySuggest, error) {
	panic("unimplemented")
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

	var eth *evm.SDK
	if ethRpc != nil {
		ethEvmChainID, err := common.Ethereum.EvmID()
		if err != nil {
			return nil, fmt.Errorf("failed to get Ethereum EVM ID: %w", err)
		}
		eth = evm.NewSDK(ethEvmChainID, ethRpc, ethRpc.Client())
	}

	return &Plugin{
		db:                    db,
		signer:                signer,
		eth:                   eth,
		logger:                logrus.WithField("plugin", "payroll"),
		txIndexerService:      txIndexerService,
		client:                client,
		vaultStorage:          vaultStorage,
		vaultEncryptionSecret: vaultEncryptionSecret,
	}, nil
}
