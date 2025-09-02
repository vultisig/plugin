package storage

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/types"
)

type DatabaseStorage interface {
	Close() error

	GetPluginPolicy(ctx context.Context, id uuid.UUID) (*vtypes.PluginPolicy, error)
	GetPluginPolicies(ctx context.Context, publicKey string, pluginID vtypes.PluginID, onlyActive bool) ([]vtypes.PluginPolicy, error)
	GetAllFeePolicies(ctx context.Context) ([]vtypes.PluginPolicy, error)
	DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id uuid.UUID) error
	InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)

	GetFeeBatch(ctx context.Context, batchIDs ...uuid.UUID) ([]types.FeeBatch, error)
	GetFeeBatchByStatus(ctx context.Context, status types.FeeBatchState) ([]types.FeeBatch, error)
	CreateFeeBatch(ctx context.Context, tx pgx.Tx, batches ...types.FeeBatch) ([]types.FeeBatch, error)
	SetFeeBatchStatus(ctx context.Context, tx pgx.Tx, batchId uuid.UUID, status types.FeeBatchState) error
	SetFeeBatchSent(ctx context.Context, tx pgx.Tx, txHash string, batchId uuid.UUID) error

	InsertTx(ctx context.Context, tx pgx.Tx, rawTx string) error
	GetTx(ctx context.Context, txHash string) (string, error)

	Pool() *pgxpool.Pool
}
