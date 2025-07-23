package plugin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/kaptinlin/jsonschema"
	"github.com/vultisig/recipes/engine"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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

func RecipeConfiguration(jsonSchema map[string]any) (*structpb.Struct, error) {
	b, err := json.Marshal(jsonSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}

	_, err = jsonschema.NewCompiler().Compile(b)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	pb, err := structpb.NewStruct(jsonSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to build pb schema: %w", err)
	}
	return pb, nil
}
