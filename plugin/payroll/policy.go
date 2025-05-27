package payroll

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	gcommon "github.com/ethereum/go-ethereum/common"
	gtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/sirupsen/logrus"
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

func (p *PayrollPlugin) ValidateProposedTransactions(policy vtypes.PluginPolicy, txs []vtypes.PluginKeysignRequest) error {
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

func (p *PayrollPlugin) ValidatePluginPolicy(policyDoc vtypes.PluginPolicy) error {
	if policyDoc.PluginID != vtypes.PluginVultisigPayroll_0000 {
		return fmt.Errorf("policy does not match plugin type, expected: %s, got: %s", vtypes.PluginVultisigPayroll_0000, policyDoc.PluginID)
	}

	var payrollPolicy PayrollPolicy
	// TODO: validate the policy recipe and convert it to PayrollPolicy
	if len(payrollPolicy.Recipients) == 0 {
		return fmt.Errorf("no recipients found in payroll policy")
	}

	if len(payrollPolicy.ChainID) != len(payrollPolicy.Recipients) {
		p.logger.WithFields(logrus.Fields{
			"chain_id_length":   payrollPolicy.ChainID,
			"recipients_length": payrollPolicy.Recipients,
		}).Error("chain_id array length does not match number of recipients")
		return fmt.Errorf("chain_id array length must match number of recipients")
	}

	if len(payrollPolicy.TokenID) != len(payrollPolicy.Recipients) {
		return fmt.Errorf("token_id array length must match number of recipients")
	}

	for _, recipient := range payrollPolicy.Recipients {
		mixedCaseAddress, err := gcommon.NewMixedcaseAddressFromString(recipient.Address)
		if err != nil {
			return fmt.Errorf("invalid recipient address: %s", recipient.Address)
		}

		// if the address is not all lowercase, check the checksum
		if strings.ToLower(recipient.Address) != recipient.Address {
			if !mixedCaseAddress.ValidChecksum() {
				return fmt.Errorf("invalid recipient address checksum: %s", recipient.Address)
			}
		}

		if recipient.Amount == "" {
			return fmt.Errorf("amount is required for recipient %s", recipient.Address)
		}

		_, ok := new(big.Int).SetString(recipient.Amount, 10)
		if !ok {
			return fmt.Errorf("invalid amount for recipient %s: %s", recipient.Address, recipient.Amount)
		}
	}

	return nil
}
