package verifierapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

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
	PolicyId              uuid.UUID `json:"policy_id" validate:"required"`
	Fees                  []FeeDto  `json:"fees" validate:"required"`
	TotalFeesIncurred     int       `json:"total_fees_incurred" validate:"required"`     // Total fees incurred in the smallest unit, e.g., "1000000" for 0.01 VULTI
	FeesPendingCollection int       `json:"fees_pending_collection" validate:"required"` // Total fees pending collection in the smallest unit, e.g., "1000000" for 0.01 VULTI
}

func (v *VerifierApi) GetPublicKeysFees(ecdsaPublicKey string) (*FeeHistoryDto, error) {
	response, err := v.getAuth(fmt.Sprintf("/fees/publickey/%s", ecdsaPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get public key fees: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			v.logger.WithError(err).Error("Failed to close response body")
		}
	}()
	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("public key not found")
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get public key fees, status code: %d", response.StatusCode)
	}

	var feeHistory APIResponse[FeeHistoryDto]
	if err := json.NewDecoder(response.Body).Decode(&feeHistory); err != nil {
		return nil, fmt.Errorf("failed to decode public key fees response: %w", err)
	}

	if feeHistory.Error.Message != "" {
		return nil, fmt.Errorf("failed to get public key fees, error: %s, details: %s", feeHistory.Error.Message, feeHistory.Error.DetailedResponse)
	}

	return &feeHistory.Data, nil
}

func (v *VerifierApi) MarkFeeAsCollected(txHash string, collectedAt time.Time, feeIds ...uuid.UUID) error {

	var body = struct {
		IDs         []uuid.UUID `json:"ids"`
		TxHash      string      `json:"tx_hash"`
		CollectedAt time.Time   `json:"collected_at"`
	}{
		IDs:         feeIds,
		TxHash:      txHash,
		CollectedAt: collectedAt,
	}

	url := "/fees/collected"
	response, err := v.postAuth(url, body)
	if err != nil {
		return fmt.Errorf("failed to mark fee as collected: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to mark fee as collected, status code: %d", response.StatusCode)
	}

	return nil
}
