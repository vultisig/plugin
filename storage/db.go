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
	GetAllPluginPolicies(ctx context.Context, publicKey string, pluginID vtypes.PluginID, onlyActive bool) ([]vtypes.PluginPolicy, error)
	DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id uuid.UUID) error
	InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)

	CreateTimeTriggerTx(ctx context.Context, dbTx pgx.Tx, trigger types.TimeTrigger) error
	GetPendingTimeTriggers(ctx context.Context) ([]types.TimeTrigger, error)
	UpdateTimeTriggerLastExecution(ctx context.Context, policyID uuid.UUID) error
	UpdateTimeTriggerTx(ctx context.Context, policyID uuid.UUID, trigger types.TimeTrigger, dbTx pgx.Tx) error

	DeleteTimeTrigger(ctx context.Context, policyID uuid.UUID) error
	UpdateTriggerStatus(ctx context.Context, policyID uuid.UUID, status types.TimeTriggerStatus) error
	GetTriggerStatus(ctx context.Context, policyID uuid.UUID) (types.TimeTriggerStatus, error)

	CreateFeeRun(ctx context.Context, policyId uuid.UUID, state types.FeeRunState, fees []verifierapi.FeeDto) (*types.FeeRun, error)

	Pool() *pgxpool.Pool
}
