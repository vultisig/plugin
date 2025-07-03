package verifierapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

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
	ID          uuid.UUID `json:"id" validate:"required"`
	Amount      int       `json:"amount" validate:"required"`
	ChargedAt   string    `json:"charged_on" validate:"required"` // "tx" or "recurring"
	Collected   bool      `json:"collected" validate:"required"`  // true if the fee is collected, false if it's just a record
	CollectedAt string    `json:"collected_at"`                   // timestamp when the fee was collected
	PublicKey   string    `json:"public_key" validate:"required"`
	PolicyId    uuid.UUID `json:"policy_id" validate:"required"`
	PluginId    string    `json:"plugin_id" validate:"required"`
}

type FeeHistoryDto struct {
	// PolicyId              uuid.UUID `json:"policy_id" validate:"required"`
	Fees                  []FeeDto `json:"fees" validate:"required"`
	TotalFeesIncurred     int      `json:"total_fees_incurred" validate:"required"`     // Total fees incurred in the smallest unit, e.g., "1000000" for 0.01 VULTI
	FeesPendingCollection int      `json:"fees_pending_collection" validate:"required"` // Total fees pending collection in the smallest unit, e.g., "1000000" for 0.01 VULTI
}

// TODO add auth
func (v VerifierApi) GetPluginPolicyFees(policyId uuid.UUID) (FeeHistoryDto, error) {
	url := fmt.Sprintf("/fees/policy/%s", policyId.String())
	v.logger.Debug("Getting plugin policy fees for policy: ", policyId.String())
	v.logger.Debug("URL: ", url)
	response, err := v.get(url)
	if err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to get plugin policy fees: %w", err)
	}
	if response.StatusCode == http.StatusNotFound {
		return FeeHistoryDto{}, fmt.Errorf("policy not found")
	}

	if response.StatusCode != http.StatusOK {
		return FeeHistoryDto{}, fmt.Errorf("failed to get plugin policy fees, status code: %d", response.StatusCode)
	}

	var feeHistory APIResponse[FeeHistoryDto]
	if err := json.NewDecoder(response.Body).Decode(&feeHistory); err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to decode plugin policy fees response: %w", err)
	}

	if feeHistory.Error.Message != "" {
		return FeeHistoryDto{}, fmt.Errorf("failed to get plugin policy fees, error: %s, details: %s", feeHistory.Error.Message, feeHistory.Error.DetailedResponse)
	}

	return feeHistory.Data, nil
}

// TODO add auth
func (v VerifierApi) GetPublicKeysFees(ecdsaPublicKey string) (FeeHistoryDto, error) {
	url := fmt.Sprintf("/fees/publickey/%s", ecdsaPublicKey)
	response, err := v.get(url)
	if err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to get public key fees: %w", err)
	}

	//TODO - this probably shouldn't be a 404, just an empty wrapped response with 0
	if response.StatusCode == http.StatusNotFound {
		return FeeHistoryDto{}, fmt.Errorf("public key not found")
	}

	if response.StatusCode != http.StatusOK {
		return FeeHistoryDto{}, fmt.Errorf("failed to get public key fees, status code: %d", response.StatusCode)
	}

	var feeHistory APIResponse[FeeHistoryDto]
	if err := json.NewDecoder(response.Body).Decode(&feeHistory); err != nil {
		return FeeHistoryDto{}, fmt.Errorf("failed to decode public key fees response: %w", err)
	}

	if feeHistory.Error.Message != "" {
		return FeeHistoryDto{}, fmt.Errorf("failed to get public key fees, error: %s, details: %s", feeHistory.Error.Message, feeHistory.Error.DetailedResponse)
	}

	return feeHistory.Data, nil
}

func (v VerifierApi) GetAllPublicKeysFees() (map[string]FeeHistoryDto, error) {
	url := "/fees/all"
	v.logger.Debug("Getting all public key fees")
	v.logger.Debug("URL: ", url)
	response, err := v.get(url)
	if err != nil {
		return map[string]FeeHistoryDto{}, fmt.Errorf("failed to get all public key fees: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return map[string]FeeHistoryDto{}, fmt.Errorf("failed to get all public key fees, status code: %d", response.StatusCode)
	}

	var apiResponse APIResponse[map[string]FeeHistoryDto]
	if err := json.NewDecoder(response.Body).Decode(&apiResponse); err != nil {
		return map[string]FeeHistoryDto{}, fmt.Errorf("failed to decode all public key fees response: %w", err)
	}
	defer response.Body.Close()

	if apiResponse.Error.Message != "" {
		return map[string]FeeHistoryDto{}, fmt.Errorf("failed to get all public key fees, error: %s, details: %s", apiResponse.Error.Message, apiResponse.Error.DetailedResponse)
	}

	return apiResponse.Data, nil
}
