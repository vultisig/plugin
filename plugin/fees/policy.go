package fees

import (
	"encoding/base64"
	"fmt"
	"slices"

	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
)

/*
	Validate that the policy is valid for the fee plugin. Chiefly, this checks:

- The policy has a valid format
- The policy is for the fee plugin
- The policy has only one rule, that it has an ID of allow-usdc-transfer-to-collector and a resource of ethereum.usdc.transfer
- The recipient address is in the whitelist
*/

func (fp *FeePlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	if policyDoc.PluginID != vtypes.PluginVultisigFees_feee {
		return fmt.Errorf("policy does not match plugin type, expected: %s, got: %s", vtypes.PluginVultisigFees_feee, policyDoc.PluginID)
	}
	var rPolicy rtypes.Policy
	policyBytes, err := base64.StdEncoding.DecodeString(policyDoc.Recipe)
	if err != nil {
		return fmt.Errorf("failed to decode policy recipe: %w", err)
	}
	if err := proto.Unmarshal(policyBytes, &rPolicy); err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	if len(rPolicy.Rules) == 0 {
		return fmt.Errorf("no rules")
	}
	if len(rPolicy.Rules) > 1 {
		return fmt.Errorf("only one rule is allowed for the fee plugin")
	}

	rule := rPolicy.Rules[0]
	if rule.Id != "allow-usdc-transfer-to-collector" {
		return fmt.Errorf("rule id must be allow-usdc-transfer-to-collector")
	}
	if rule.Resource != "ethereum.usdc.transfer" {
		return fmt.Errorf("rule resource must be ethereum.usdc.transfer")
	}

	// Validate that recipient address is in the whitelist
	var recipient string
	for _, constraint := range rule.ParameterConstraints {
		if constraint.ParameterName == "recipient" {
			if constraint.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
				return fmt.Errorf("recipient constraint must be a fixed value")
			}
			fixedValue := constraint.Constraint.GetValue().(*rtypes.Constraint_FixedValue)
			recipient = fixedValue.FixedValue
			break
		}
	}

	if recipient == "" {
		return fmt.Errorf("recipient parameter constraint is required")
	}

	// Check if recipient is in the whitelist
	if !slices.Contains(fp.config.CollectorWhitelistAddresses, recipient) {
		return fmt.Errorf("recipient address %s is not in the whitelist: %v", recipient, fp.config.CollectorWhitelistAddresses)
	}

	return nil
}

func (fp FeePlugin) GetRecipeSpecification() rtypes.RecipeSchema {
	return rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		PluginId:        string(vtypes.PluginVultisigFees_feee.String()),
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
