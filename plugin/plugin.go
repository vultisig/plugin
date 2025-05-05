package plugin

import (
	"context"
	"embed"

	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/vultiserver-plugin/internal/types"
	vtypes "github.com/vultisig/verifier/types"
)

type Plugin interface {
	FrontendSchema() embed.FS
	ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error
	ProposeTransactions(policy vtypes.PluginPolicy) ([]types.PluginKeysignRequest, error)
	ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []types.PluginKeysignRequest) error
	SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest types.PluginKeysignRequest, policy vtypes.PluginPolicy) error
}
