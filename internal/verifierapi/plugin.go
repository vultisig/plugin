package verifierapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func (v VerifierApi) GetPolicy() string {
	return "verifierapi"
}

// func (v VerifierApi) CreatePluginPolicy() (ptypes.PluginPolicy, error) {
// 	url := "/policy"
// 	method := http.MethodPost
// }
// func (v VerifierApi) UpdatePluginPolicyById() {
// 	url := "/policy"
// 	method := http.MethodPut
// }
// func (v VerifierApi) GetAllPluginPolicies() {
// 	url := "/policies"
// 	method := http.MethodGet
// }
// func (v VerifierApi) GetPluginPolicyById() {
// 	url := "/policy/:policyId"
// 	method := http.MethodGet
// }
// func (v VerifierApi) DeletePluginPolicyById() {
// 	url := "/policy/:policyId"
// 	method := http.MethodDelete
// }
// func (v VerifierApi) GetPluginPolicyTransactionHistory() {
// 	url := "/policies/:policyId/history"
// 	method := http.MethodGet
// }

// dto types
type FeeDto struct {
	Amount      int    `json:"amount" validate:"required"`
	ChargedAt   string `json:"charged_on" validate:"required"` // "tx" or "recurring"
	Collected   bool   `json:"collected" validate:"required"`  // true if the fee is collected, false if it's just a record
	CollectedAt string `json:"collected_at"`                   // timestamp when the fee was collected
}

type FeeHistoryDto struct {
	PolicyId              uuid.UUID `json:"policy_id" validate:"required"`
	Fees                  []FeeDto  `json:"fees" validate:"required"`
	TotalFeesIncurred     int       `json:"total_fees_incurred" validate:"required"`     // Total fees incurred in the smallest unit, e.g., "1000000" for 0.01 VULTI
	FeesPendingCollection int       `json:"fees_pending_collection" validate:"required"` // Total fees pending collection in the smallest unit, e.g., "1000000" for 0.01 VULTI
}

// TODO add auth
func (v VerifierApi) GetPluginPolicyFees(policyId uuid.UUID) (FeeHistoryDto, error) {
	url := fmt.Sprintf("/policies/%s/fees", policyId.String())
	response, err := v.get(url)
	if err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to get plugin policy fees: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return FeeHistoryDto{}, fmt.Errorf("failed to get plugin policy fees, status code: %d", response.StatusCode)
	}
	var feeHistory FeeHistoryDto
	if err := json.NewDecoder(response.Body).Decode(&feeHistory); err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to decode plugin policy fees response: %w", err)
	}
	return feeHistory, nil
}
