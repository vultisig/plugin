package payroll

import (
	"fmt"
	"strings"

	"github.com/vultisig/plugin/internal/plugin"
	"github.com/vultisig/recipes/chain"
	"github.com/vultisig/recipes/engine"
	vtypes "github.com/vultisig/verifier/types"
)

func (p *PayrollPlugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
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

func (p *PayrollPlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	return plugin.ValidatePluginPolicy(policyDoc, p.GetRecipeSpecification())
}
