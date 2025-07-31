package fees

import (
	"fmt"

	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
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
	spec, err := fp.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to get recipe spec: %w", err)
	}
	return plugin.ValidatePluginPolicy(policyDoc, spec)
}

func (fp *FeePlugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {

	cfg, err := plugin.RecipeConfiguration(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("failed to build pb recipe config: %w", err)
	}

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
					Full:       "ethereum.erc20.transfer",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "recipient",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAGIC_CONSTANT,
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
					{
						ParameterName: "token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
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
		Configuration: cfg,
	}, nil
}
