package types

import (
	"time"

	"github.com/google/uuid"
)

// DB FEE Types

type FeeBatchState string

const (
	FeeBatchStateDraft   FeeBatchState = "draft"
	FeeBatchStateSent    FeeBatchState = "sent"
	FeeBatchStateSuccess FeeBatchState = "completed"
	FeeBatchStateFailed  FeeBatchState = "failed"
)

// individual fee record in the db
type FeeBatch struct {
	ID        uuid.UUID     `db:"id"`
	BatchID   uuid.UUID     `db:"batch_id"`
	PublicKey string        `db:"public_key"`
	Status    FeeBatchState `db:"status"`
	Amount    uint64        `db:"amount"`
	CreatedAt time.Time     `db:"created_at"`
	UpdatedAt time.Time     `db:"updated_at"`
	TxHash    *string       `db:"tx_hash"`
}
