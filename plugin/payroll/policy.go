package payroll

import (
	"encoding/base64"
	"fmt"

	"github.com/vultisig/recipes/engine"
	"github.com/vultisig/verifier/plugin"
	vtypes "github.com/vultisig/verifier/types"
	vgcommon "github.com/vultisig/vultisig-go/common"
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
			txBytes, err := base64.StdEncoding.DecodeString(keysignMessage.Message)
			if err != nil {
				return fmt.Errorf("failed to decode transaction: %w", err)
			}

			_, err = eng.Evaluate(recipe, vgcommon.Chain(keysignMessage.Chain), txBytes)
			if err != nil {
				return fmt.Errorf("failed to evaluate transaction: %w", err)
			}
		}
	}

	return nil
}

func (p *Plugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	spec, err := p.GetRecipeSpecification()
	if err != nil {
		return fmt.Errorf("failed to build recipe spec: %w", err)
	}

	return plugin.ValidatePluginPolicy(policyDoc, spec)
}
