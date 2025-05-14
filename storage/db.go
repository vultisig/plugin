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

	FindUserById(ctx context.Context, userId string) (*types.User, error)
	FindUserByName(ctx context.Context, username string) (*types.UserWithPassword, error)

	GetPluginPolicy(ctx context.Context, id string) (vtypes.PluginPolicy, error)
	GetAllPluginPolicies(ctx context.Context, publicKey string, pluginType string) ([]vtypes.PluginPolicy, error)
	DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id string) error
	InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)

	FindPricingById(ctx context.Context, id string) (*types.Pricing, error)
	CreatePricing(ctx context.Context, pricingDto types.PricingCreateDto) (*types.Pricing, error)
	DeletePricingById(ctx context.Context, id string) error

	CreateTimeTriggerTx(ctx context.Context, dbTx pgx.Tx, trigger types.TimeTrigger) error
	GetPendingTimeTriggers(ctx context.Context) ([]types.TimeTrigger, error)
	UpdateTimeTriggerLastExecution(ctx context.Context, policyID uuid.UUID) error
	UpdateTimeTriggerTx(ctx context.Context, policyID uuid.UUID, trigger types.TimeTrigger, dbTx pgx.Tx) error

	DeleteTimeTrigger(ctx context.Context, policyID uuid.UUID) error
	UpdateTriggerStatus(ctx context.Context, policyID uuid.UUID, status types.TimeTriggerStatus) error
	GetTriggerStatus(ctx context.Context, policyID uuid.UUID) (types.TimeTriggerStatus, error)

	CountTransactions(ctx context.Context, policyID uuid.UUID, status types.TransactionStatus, txType string) (int64, error)
	CreateTransactionHistoryTx(ctx context.Context, dbTx pgx.Tx, tx types.TransactionHistory) (uuid.UUID, error)
	UpdateTransactionStatusTx(ctx context.Context, dbTx pgx.Tx, txID uuid.UUID, status types.TransactionStatus, metadata map[string]interface{}) error
	CreateTransactionHistory(ctx context.Context, tx types.TransactionHistory) (uuid.UUID, error)
	UpdateTransactionStatus(ctx context.Context, txID uuid.UUID, status types.TransactionStatus, metadata map[string]interface{}) error
	GetTransactionHistory(ctx context.Context, policyID uuid.UUID, transactionType string, take int, skip int) ([]types.TransactionHistory, error)
	GetTransactionByHash(ctx context.Context, txHash string) (*types.TransactionHistory, error)

	Pool() *pgxpool.Pool
}
