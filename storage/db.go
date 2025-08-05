package storage

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
)

type DatabaseStorage interface {
	Close() error

	GetPluginPolicy(ctx context.Context, id uuid.UUID) (*vtypes.PluginPolicy, error)
	GetPluginPolicies(ctx context.Context, publicKey string, pluginID vtypes.PluginID, onlyActive bool) ([]vtypes.PluginPolicy, error)
	GetAllFeePolicies(ctx context.Context) ([]vtypes.PluginPolicy, error)
	DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id uuid.UUID) error
	InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)

	CreateFeeRun(ctx context.Context, policyId uuid.UUID, state types.FeeRunState, fees ...verifierapi.FeeDto) (*types.FeeRun, error)
	SetFeeRunSent(ctx context.Context, runId uuid.UUID, txHash string) error
	SetFeeRunSuccess(ctx context.Context, runId uuid.UUID) error
	GetAllFeeRuns(ctx context.Context, statuses ...types.FeeRunState) ([]types.FeeRun, error) // If no statuses are provided, all fee runs are returned.
	GetFees(ctx context.Context, feeIds ...uuid.UUID) ([]types.Fee, error)
	GetPendingFeeRun(ctx context.Context, policyId uuid.UUID) (*types.FeeRun, error)
	CreateFee(ctx context.Context, runId uuid.UUID, fee verifierapi.FeeDto) error
	GetFeeRuns(ctx context.Context, state types.FeeRunState) ([]types.FeeRun, error)

	Pool() *pgxpool.Pool
}
