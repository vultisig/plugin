package verifierapi

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/vultisig/plugin/internal/types"
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

type FeeBalanceDto struct {
	Balance   int64  `json:"balance" validate:"required"`
	PublicKey string `json:"public_key" validate:"required"`
}

type FeeBatchCreateResponseDto struct {
	PublicKey string    `json:"public_key" validate:"required"`
	Amount    uint64    `json:"amount" validate:"required"`
	BatchID   uuid.UUID `json:"batch_id" validate:"required"`
}

type FeeBatchUpdateRequestResponseDto struct {
	PublicKey string              `json:"public_key" validate:"required"`
	BatchID   uuid.UUID           `json:"batch_id" validate:"required"`
	TxHash    string              `json:"tx_hash" validate:"required"`
	Status    types.FeeBatchState `json:"status" validate:"required"`
}

func (v *VerifierApi) CreateFeeBatch(publicKey string) (*FeeBatchCreateResponseDto, error) {
	response, err := v.postAuth("/fees/batch", map[string]interface{}{
		"public_key": publicKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create fee batch: %w", err)
	}
	defer response.Body.Close()

	var feeBatchResponse APIResponse[FeeBatchCreateResponseDto]
	if err := json.NewDecoder(response.Body).Decode(&feeBatchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode fee batch response: %w", err)
	}

	return &feeBatchResponse.Data, nil
}

func (v *VerifierApi) GetDraftBatches(publicKey string) ([]FeeBatchCreateResponseDto, error) {
	response, err := v.getAuth(fmt.Sprintf("/fees/batch/draft/%s", publicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get draft batches: %w", err)
	}
	defer response.Body.Close()

	var feeBatches APIResponse[[]FeeBatchCreateResponseDto]
	if err := json.NewDecoder(response.Body).Decode(&feeBatches); err != nil {
		return nil, fmt.Errorf("failed to decode fee batches response: %w", err)
	}

	return feeBatches.Data, nil
}

func (v *VerifierApi) GetFeeHistory(ecdsaPublicKey string) (*FeeHistoryDto, error) {
	response, err := v.getAuth(fmt.Sprintf("/fees/history/%s", ecdsaPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get public key fees: %w", err)
	}
	defer response.Body.Close()
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

func (v *VerifierApi) GetFeeBalance(ecdsaPublicKey string) (*FeeBalanceDto, error) {
	response, err := v.getAuth(fmt.Sprintf("/fees/balance/%s", ecdsaPublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to get public key fees: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("public key not found")
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get public key fees, status code: %d", response.StatusCode)
	}

	var feeBalance APIResponse[FeeBalanceDto]
	if err := json.NewDecoder(response.Body).Decode(&feeBalance); err != nil {
		return nil, fmt.Errorf("failed to decode public key fees response: %w", err)
	}

	return &feeBalance.Data, nil
}

func (v *VerifierApi) CreateFeeCredit(id uuid.UUID, amount int64, publicKey string) error {
	response, err := v.postAuth("/fees/credit", map[string]interface{}{
		"id":         id,
		"amount":     amount,
		"public_key": publicKey,
	})
	if err != nil {
		return fmt.Errorf("failed to create fee credit: %w", err)
	}
	defer response.Body.Close()

	return nil
}

func (v *VerifierApi) UpdateFeeBatch(publickey string, batchId uuid.UUID, hash string, status types.FeeBatchState) (*APIResponse[FeeBatchCreateResponseDto], error) {
	response, err := v.putAuth("/fees/batch", FeeBatchUpdateRequestResponseDto{
		PublicKey: publickey,
		BatchID:   batchId,
		TxHash:    hash,
		Status:    status,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get fee batch: %w", err)
	}
	defer response.Body.Close()
	var feeBatchResponse APIResponse[FeeBatchCreateResponseDto]
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to update fee batch, status code: %d", response.StatusCode)
	}
	if err := json.NewDecoder(response.Body).Decode(&feeBatchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode fee batch response: %w", err)
	}

	return &feeBatchResponse, nil
}
