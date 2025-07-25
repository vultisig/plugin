package copytrader

import (
	"fmt"
	"strings"

	"github.com/vultisig/recipes/chain"
	"github.com/vultisig/recipes/engine"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/plugin"
)

func (p *Plugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	recipe, err := policy.GetRecipe()
	if err != nil {
		return fmt.Errorf("failed to get recipe from policy: %v", err)
	}

	eng := engine.NewEngine()

	for _, tx := range txs {
		for _, keysignMessage := range tx.Messages {
			messageChain, err := chain.GetChain(strings.ToLower(keysignMessage.Chain.String()))
			if err != nil {
				return fmt.Errorf("failed to get chain: %w", err)
			}

			decodedTx, err := messageChain.ParseTransaction(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to parse transaction: %w", err)
			}

			transactionAllowed, _, err := eng.Evaluate(recipe, messageChain, decodedTx)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}

			if !transactionAllowed {
				return fmt.Errorf("transaction %s on %s not allowed by policy", keysignMessage.Hash, keysignMessage.Chain)
			}
		}
	}

	return nil
}

func (p *Plugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, p.GetRecipeSpecification())
}

func (p *Plugin) GetRecipeSpecification() *rtypes.RecipeSchema {
	return &rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		// TODO: configure
		PluginId:      string(vtypes.PluginVultisigCopytrader_0000),
		PluginName:    "Copy trading plugin",
		PluginVersion: 1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapv2_router",
					FunctionId: "swapExactTokensForTokens",
					Full:       "ethereum.uniswapv2_router.swapExactTokensForTokens",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "aim",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "source_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "destination_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX,
							rtypes.ConstraintType_CONSTRAINT_TYPE_RANGE,
						},
						Required: true,
					},
				},
				Required: true,
			},
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}
