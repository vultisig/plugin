package plugin

import (
	"encoding/base64"
	"fmt"

	"github.com/vultisig/recipes/engine"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
)

func ValidatePluginPolicy(policyDoc vtypes.PluginPolicy, spec *rtypes.RecipeSchema) error {
	policyBytes, err := base64.StdEncoding.DecodeString(policyDoc.Recipe)
	if err != nil {
		return fmt.Errorf("failed to decode policy recipe: %w", err)
	}

	var rPolicy rtypes.Policy
	err = proto.Unmarshal(policyBytes, &rPolicy)
	if err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	err = engine.NewEngine().ValidatePolicyWithSchema(&rPolicy, spec)
	if err != nil {
		return fmt.Errorf("failed to validate policy: %w", err)
	}
	return nil
}
