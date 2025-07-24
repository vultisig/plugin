package payroll

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/verifier/types"
)

type SchedulerService struct {
	repo scheduler.Storage
}

func NewSchedulerService(repo scheduler.Storage) *SchedulerService {
	return &SchedulerService{
		repo: repo,
	}
}

func (s *SchedulerService) Create(ctx context.Context, tx pgx.Tx, policy types.PluginPolicy) error {
	start, err := startDateFromPolicy(policy)
	if err != nil {
		return fmt.Errorf("fauiled to unpack start date from policy: %w", err)
	}
	return s.repo.CreateWithTx(ctx, tx, policy.ID, start)
}

func startDateFromPolicy(policy types.PluginPolicy) (time.Time, error) {
	recipe, err := policy.GetRecipe()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to unpack recipe: %w", err)
	}

	cfg := recipe.GetConfiguration().GetFields()

	start := time.Now()
	cfgStartDate := cfg[startDate].GetStringValue()
	if cfgStartDate != "" {
		t, er := time.Parse(time.RFC3339, cfgStartDate)
		if er != nil {
			return time.Time{}, fmt.Errorf("failed to parse start date (%s): %w", cfgStartDate, er)
		}
		start = t
	}
	return start, nil
}

func (s *SchedulerService) Update(ctx context.Context, tx pgx.Tx, oldPolicy, newPolicy types.PluginPolicy) error {
	oldStart, err := startDateFromPolicy(oldPolicy)
	if err != nil {
		return fmt.Errorf("failed to unpack start date from policy: %w", err)
	}
	newStart, err := startDateFromPolicy(newPolicy)
	if err != nil {
		return fmt.Errorf("failed to unpack start date from policy: %w", err)
	}
	if oldStart.Equal(newStart) {
		// no changes
		return nil
	}

	return s.repo.SetNextWithTx(ctx, tx, oldPolicy.ID, newStart)
}

func (s *SchedulerService) Delete(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error {
	return s.repo.DeleteWithTx(ctx, tx, policyID)
}
