package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/sirupsen/logrus"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/storage"
)

type Policy interface {
	CreatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	UpdatePolicy(ctx context.Context, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error)
	DeletePolicy(ctx context.Context, policyID uuid.UUID, signature string) error
	GetPluginPolicies(ctx context.Context, pluginID vtypes.PluginID, publicKey string, onlyActive bool) ([]vtypes.PluginPolicy, error)
	GetPluginPolicy(ctx context.Context, policyID uuid.UUID) (*vtypes.PluginPolicy, error)
}

var _ Policy = (*PolicyService)(nil)

type PolicyService struct {
	db        storage.DatabaseStorage
	scheduler *scheduler.Service
	logger    *logrus.Logger
}

func NewPolicyService(db storage.DatabaseStorage, scheduler *scheduler.Service, logger *logrus.Logger) (*PolicyService, error) {
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
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
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

	if err := s.scheduler.Create(ctx, tx, policy); err != nil {
		return nil, fmt.Errorf("failed to create time trigger: %w", err)
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

func (s *PolicyService) GetPluginPolicies(ctx context.Context, pluginID vtypes.PluginID, publicKey string, onlyActive bool) ([]vtypes.PluginPolicy, error) {
	return s.db.GetAllPluginPolicies(ctx, publicKey, pluginID, onlyActive)
}

func (s *PolicyService) GetPluginPolicy(ctx context.Context, policyID uuid.UUID) (*vtypes.PluginPolicy, error) {
	return s.db.GetPluginPolicy(ctx, policyID)
}
