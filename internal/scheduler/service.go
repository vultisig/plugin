package scheduler

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/vultisig/verifier/types"
)

type Service interface {
	Create(ctx context.Context, tx pgx.Tx, policy types.PluginPolicy) error
	Update(ctx context.Context, tx pgx.Tx, oldPolicy, newPolicy types.PluginPolicy) error
	Delete(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error
}
