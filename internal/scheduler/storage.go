package scheduler

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Scheduler struct {
	PolicyID      uuid.UUID `json:"policy_id"`
	NextExecution time.Time `json:"next_execution"`
}

type Storage interface {
	CreateWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID, next time.Time) error
	DeleteWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error
	GetPending(ctx context.Context) ([]Scheduler, error)
	SetNext(ctx context.Context, policyID uuid.UUID, next time.Time) error
}
