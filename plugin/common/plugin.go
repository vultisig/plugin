package common

import (
	"context"

	"github.com/vultisig/mobile-tss-lib/tss"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/types"
)

type Plugin interface {
	GetRecipeSpecification() *rtypes.RecipeSchema

	ValidatePluginPolicy(policyDoc types.PluginPolicy) error       // Used for validating a document that already exists when signing a transaction. Mostly checks on typing and constraints.
	ValidateUpdatePluginPolicy(policyDoc types.PluginPolicy) error // Additional validations for updating a policy.
	ValidateCreatePluginPolicy(policyDoc types.PluginPolicy) error // Additional validations for creating a policy. e.g. can't create more than one fee policy
	ValidateDeletePluginPolicy(policyDoc types.PluginPolicy) error // Additional validations for deleting a policy. e.g. can't delete fee policy if there are fees still pending collection or other active plugins

	ProposeTransactions(policy types.PluginPolicy) ([]types.PluginKeysignRequest, error)
	ValidateProposedTransactions(policy types.PluginPolicy, txs []types.PluginKeysignRequest) error
	SigningComplete(ctx context.Context, signature tss.KeysignResponse, signRequest types.PluginKeysignRequest, policy types.PluginPolicy) error
}
