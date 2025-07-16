package fees

import (
	"github.com/vultisig/plugin/internal/plugin"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
)

/*
	Validate that the policy is valid for the fee plugin. Chiefly, this checks:

- The policy has a valid format
- The policy is for the fee plugin
- The policy has only one rule, that it has an ID of allow-usdc-transfer-to-collector and a resource of ethereum.usdc.transfer
- The recipient address is in the whitelist
*/

func (fp *FeePlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, fp.GetRecipeSpecification())
}

func (fp *FeePlugin) ValidateUpdatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, fp.GetRecipeSpecification())
}

func (fp *FeePlugin) ValidateCreatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, fp.GetRecipeSpecification())
}

func (fp *FeePlugin) ValidateDeletePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, fp.GetRecipeSpecification())
}

func (fp *FeePlugin) GetRecipeSpecification() *rtypes.RecipeSchema {
	return &rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		PluginId:        vtypes.PluginVultisigFees_feee.String(),
		PluginName:      "Fee Plugin",
		PluginVersion:   1,
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "usdc",
					FunctionId: "transfer",
					Full:       "ethereum.usdc.transfer",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "recipient",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX,
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
