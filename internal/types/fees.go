package types

import (
	"time"

	"github.com/google/uuid"
)

// DB FEE Types

type FeeRunState string

const (
	FeeRunStateDraft FeeRunState = "draft"
	FeeRunStateSent  FeeRunState = "sent"
)

// individual fee record in the db
type Fee struct {
	ID        uuid.UUID `db:"id"`
	FeeRunID  uuid.UUID `db:"fee_run_id"`
	Amount    int       `db:"amount"`
	CreatedAt time.Time `db:"created_at"`
}

// fee table or fee_run_with_totals
type FeeRun struct {
	ID          uuid.UUID   `db:"id"`
	Status      FeeRunState `db:"status"`
	CreatedAt   time.Time   `db:"created_at"`
	UpdatedAt   time.Time   `db:"updated_at"`
	TxID        *uuid.UUID  `db:"tx_id"`
	PolicyID    uuid.UUID   `db:"policy_id"`
	TotalAmount int         `db:"total_amount"`
	FeeCount    int         `db:"fee_count"`
}
