package fees

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/storage"
	rtypes "github.com/vultisig/recipes/types"
)

var _ plugin.Plugin = (*FeePlugin)(nil)

type FeePlugin struct {
	db        storage.DatabaseStorage
	rpcClient *ethclient.Client
	logger    logrus.FieldLogger
	config    *PluginConfig
}

// TODO garry, this needs work
func NewFeePlugin(db storage.DatabaseStorage, logger logrus.FieldLogger, baseConfigPath string) (*FeePlugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	cfg, err := NewPluginConfig(WithFileConfig(baseConfigPath))
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin config: %w", err)
	}

	rpcClient, err := ethclient.Dial(cfg.RpcURL)
	if err != nil {
		return nil, err
	}

	return &FeePlugin{
		db:        db,
		rpcClient: rpcClient,
		logger:    logger.WithField("plugin", "fees"),
		config:    cfg,
	}, nil
}

func (fp *FeePlugin) GetRecipeSpecification() rtypes.RecipeSchema {
	fp.logger.Debug("Getting recipe specification")
	//TODO garry
	return rtypes.RecipeSchema{
		PluginId: "vultisig-fees-fees",
		Version:  1,
	}
}

// TODO garry all
func (fp *FeePlugin) ValidatePluginPolicy(policyDoc types.PluginPolicy) error {
	return nil
}
func (fp *FeePlugin) ProposeTransactions(policy types.PluginPolicy) ([]types.PluginKeysignRequest, error) {
	return []types.PluginKeysignRequest{}, nil
}
func (fp *FeePlugin) ValidateProposedTransactions(policy types.PluginPolicy, txs []types.PluginKeysignRequest) error {
	return nil
}
func (fp *FeePlugin) SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest types.PluginKeysignRequest, policy types.PluginPolicy) error {
	return nil
}
