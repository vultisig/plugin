package payroll

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	gcommon "github.com/ethereum/go-ethereum/common"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/golang/protobuf/proto"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"
)

type PayrollPolicy struct {
	ChainID    []string           `json:"chain_id"`
	TokenID    []string           `json:"token_id"`
	Recipients []PayrollRecipient `json:"recipients"`
	Schedule   Schedule           `json:"schedule"`
}

type PayrollRecipient struct {
	Address string `json:"address"`
	Amount  string `json:"amount"`
}

// This is duplicated between DCA and Payroll to avoid a
// circular top-level dependency on the types package
type Schedule struct {
	Frequency string `json:"frequency"`
	Interval  string `json:"interval"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time,omitempty"`
}

func (p *PayrollPlugin) ValidateProposedTransactions(policy vtypes.PluginPolicyCreateUpdate, txs []vtypes.PluginKeysignRequest) error {
	err := p.ValidatePluginPolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to validate plugin policy: %v", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(erc20ABI))
	if err != nil {
		return fmt.Errorf("failed to parse ABI: %v", err)
	}

	var payrollPolicy PayrollPolicy
	// TODO: convert the recipes to PayrollPolicy
	for i, tx := range txs {
		var parsedTx *gtypes.Transaction
		txBytes, err := hex.DecodeString(tx.Transaction)
		if err != nil {
			return fmt.Errorf("failed to decode transaction: %v", err)
		}

		err = rlp.DecodeBytes(txBytes, &parsedTx)
		if err != nil {
			return fmt.Errorf("failed to parse transaction: %v", err)
		}

		txDestination := parsedTx.To()
		if txDestination == nil {
			return fmt.Errorf("transaction destination is nil")
		}

		if strings.ToLower(txDestination.Hex()) != strings.ToLower(payrollPolicy.TokenID[i]) { // todo : why we compare to tokenId and not recipient address?
			return fmt.Errorf("transaction destination does not match token ID")
		}

		txData := parsedTx.Data()
		m, err := parsedABI.MethodById(txData[:4])
		if err != nil {
			return fmt.Errorf("failed to get method by ID: %v", err)
		}

		v := make(map[string]interface{})
		if err := m.Inputs.UnpackIntoMap(v, txData[4:]); err != nil {
			return fmt.Errorf("failed to unpack transaction data: %v", err)
		}

		fmt.Printf("Decoded: %+v\n", v)

		recipientAddress, ok := v["recipient"].(gcommon.Address)
		if !ok {
			return fmt.Errorf("failed to get recipient address")
		}

		var recipientFound bool
		for _, recipient := range payrollPolicy.Recipients {
			if strings.EqualFold(recipientAddress.Hex(), recipient.Address) {
				recipientFound = true
				break
			}
		}

		if !recipientFound {
			return fmt.Errorf("recipient not found in policy")
		}
	}

	return nil
}

func (p *PayrollPlugin) validateRecipient(pc *rtypes.ParameterConstraint) error {
	if pc == nil {
		return fmt.Errorf("recipient parameter constraint is nil")
	}
	if pc.Constraint == nil {
		return fmt.Errorf("recipient constraint is nil")
	}
	if pc.ParameterName != "recipient" {
		return fmt.Errorf("expected recipient parameter, got: %s", pc.ParameterName)
	}
	if !pc.Constraint.Required {
		return fmt.Errorf("recipient constraint is required, but not set")
	}
	if pc.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
		return fmt.Errorf("recipient constraint must be fixed, got: %s", pc.Constraint.Type)
	}
	if _, err := gcommon.NewMixedcaseAddressFromString(pc.Constraint.GetFixedValue()); err != nil {
		return fmt.Errorf("invalid recipient address: %s, error: %w", pc.Constraint.GetFixedValue(), err)
	}
	return nil
}

func (p *PayrollPlugin) validateAmount(pc *rtypes.ParameterConstraint) error {
	if pc == nil {
		return fmt.Errorf("amount parameter constraint is nil")
	}
	if pc.ParameterName != "amount" {
		return fmt.Errorf("expected amount parameter, got: %s", pc.ParameterName)
	}
	if pc.Constraint == nil {
		return fmt.Errorf("amount constraint is nil")
	}
	if !pc.Constraint.Required {
		return fmt.Errorf("amount constraint is required, but not set")
	}
	if pc.Constraint.Type != rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED {
		return fmt.Errorf("amount constraint must be fixed, got: %s", pc.Constraint.Type)
	}
	if _, ok := new(big.Int).SetString(pc.Constraint.GetFixedValue(), 10); !ok {
		return fmt.Errorf("invalid amount: %s", pc.Constraint.GetFixedValue())
	}

	if !strings.EqualFold(pc.Constraint.DenominatedIn, "wei") {
		return fmt.Errorf("amount constraint must be denominated in wei, got: %s", pc.Constraint.DenominatedIn)
	}
	return nil
}
func (p *PayrollPlugin) validateSchedule(schedule *rtypes.Schedule) error {
	if schedule == nil {
		return fmt.Errorf("schedule is nil")
	}
	if schedule.GetFrequency() == rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_UNSPECIFIED {
		return fmt.Errorf("schedule frequency is required")
	}

	if schedule.GetStartTime() == nil {
		return fmt.Errorf("start time is required")
	}

	if schedule.GetEndTime() != nil && schedule.GetEndTime().AsTime().Before(schedule.GetStartTime().AsTime()) {
		return fmt.Errorf("end time cannot be before start time")
	}

	return nil
}
func (p *PayrollPlugin) checkRule(rule *rtypes.Rule) error {
	if rule.Effect != rtypes.Effect_EFFECT_ALLOW {
		return fmt.Errorf("rule effect must be ALLOW, got: %s", rule.Effect)
	}
	var seenRecipient, seenAmount bool
	for _, pc := range rule.ParameterConstraints {
		switch pc.ParameterName {
		case "recipient":
			if err := p.validateRecipient(pc); err != nil {
				return fmt.Errorf("recipient validation failed: %w", err)
			}
			seenRecipient = true
		case "amount":
			if err := p.validateAmount(pc); err != nil {
				return fmt.Errorf("amount validation failed: %w", err)
			}
			seenAmount = true
		default:
			return fmt.Errorf("unknown parameter: %s", pc.ParameterName)
		}
	}
	if !seenRecipient && !seenAmount {
		return fmt.Errorf("rule must contain at least one recipient or amount parameter")
	}
	return nil
}
func (p *PayrollPlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicyCreateUpdate) error {
	if policyDoc.PluginID != vtypes.PluginVultisigPayroll_0000 {
		return fmt.Errorf("policy does not match plugin type, expected: %s, got: %s", vtypes.PluginVultisigPayroll_0000, policyDoc.PluginID)
	}
	var rPolicy rtypes.Policy

	policyBytes, err := base64.RawStdEncoding.DecodeString(policyDoc.Recipe)
	if err != nil {
		return fmt.Errorf("failed to decode policy recipe: %w", err)
	}

	if err := proto.Unmarshal(policyBytes, &rPolicy); err != nil {
		return fmt.Errorf("failed to unmarshal policy: %w", err)
	}
	if rPolicy.Schedule == nil {
		return fmt.Errorf("policy schedule is nil")
	}

	if len(rPolicy.Rules) == 0 {
		return fmt.Errorf("no rules")
	}
	if err := p.validateSchedule(rPolicy.Schedule); err != nil {
		return fmt.Errorf("schedule validation failed: %w", err)
	}
	for _, rule := range rPolicy.Rules {
		if err := p.checkRule(rule); err != nil {
			return fmt.Errorf("rule validation failed: %w", err)
		}
	}

	return nil
}
