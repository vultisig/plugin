package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/storage"
)

type Policy interface {
	CreatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	DeletePolicy(ctx context.Context, policyID uuid.UUID, signature string) error
	GetPluginPolicies(ctx context.Context, pluginID vtypes.PluginID, publicKey string) ([]vtypes.PluginPolicy, error)
	GetPluginPolicy(ctx context.Context, policyID uuid.UUID) (vtypes.PluginPolicy, error)
	GetPluginPolicyTransactionHistory(ctx context.Context, policyID string) ([]types.TransactionHistory, error)
}

var _ Policy = (*PolicyService)(nil)

type PolicyService struct {
	db        storage.DatabaseStorage
	scheduler *scheduler.SchedulerService
	logger    *logrus.Logger
}

func NewPolicyService(db storage.DatabaseStorage, scheduler *scheduler.SchedulerService, logger *logrus.Logger) (*PolicyService, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}
	return &PolicyService{
		db:        db,
		scheduler: scheduler,
		logger:    logger,
	}, nil
}

func (s *PolicyService) handleRollback(ctx context.Context, tx pgx.Tx) {
	if err := tx.Rollback(ctx); err != nil {
		s.logger.WithError(err).Error("failed to rollback transaction")
	}
}

func (s *PolicyService) CreatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error) {
	// Start transaction
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer s.handleRollback(ctx, tx)

	// Insert policy
	newPolicy, err := s.db.InsertPluginPolicyTx(ctx, tx, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to insert policy: %w", err)
	}

	// Handle trigger if scheduler exists
	if s.scheduler != nil {
		if err := s.scheduler.CreateTimeTrigger(ctx, policy, tx); err != nil {
			return nil, fmt.Errorf("failed to create time trigger: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return newPolicy, nil
}

func (s *PolicyService) UpdatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error) {
	// start transaction
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer s.handleRollback(ctx, tx)

	// Update policy with tx
	updatedPolicy, err := s.db.UpdatePluginPolicyTx(ctx, tx, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	if s.scheduler != nil {
		trigger, err := s.scheduler.GetTriggerFromPolicy(policy)
		if err != nil {
			return nil, fmt.Errorf("failed to get trigger from policy: %w", err)
		}

		if err := s.db.UpdateTimeTriggerTx(ctx, policy.ID, *trigger, tx); err != nil {
			return nil, fmt.Errorf("failed to update trigger execution tx: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return updatedPolicy, nil
}

func (s *PolicyService) DeletePolicy(ctx context.Context, policyID uuid.UUID, signature string) error {

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer s.handleRollback(ctx, tx)

	err = s.db.DeletePluginPolicyTx(ctx, tx, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *PolicyService) GetPluginPolicies(ctx context.Context, pluginID vtypes.PluginID, publicKey string) ([]vtypes.PluginPolicy, error) {
	policies, err := s.db.GetAllPluginPolicies(ctx, publicKey, pluginID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}
	return policies, nil
}

func (s *PolicyService) GetPluginPolicy(ctx context.Context, policyID uuid.UUID) (vtypes.PluginPolicy, error) {
	policy, err := s.db.GetPluginPolicy(ctx, policyID)
	if err != nil {
		return vtypes.PluginPolicy{}, fmt.Errorf("failed to get policy: %w", err)
	}
	return policy, nil
}

func (s *PolicyService) GetPluginPolicyTransactionHistory(ctx context.Context, policyID string) ([]types.TransactionHistory, error) {
	// Convert string to UUID
	policyUUID, err := uuid.Parse(policyID)
	if err != nil {
		return []types.TransactionHistory{}, fmt.Errorf("invalid policy_id: %s", policyID)
	}

	history, err := s.db.GetTransactionHistory(ctx, policyUUID, "SWAP", 30, 0) // take the last 30 records and skip the first 0
	if err != nil {
		return []types.TransactionHistory{}, fmt.Errorf("failed to get policy history: %w", err)
	}

	return history, nil
}
