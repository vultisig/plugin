package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/types"
	"google.golang.org/protobuf/proto"
)

type Service struct {
	repo Storage
}

func NewService(repo Storage) *Service {
	return &Service{
		repo: repo,
	}
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, policy types.PluginPolicy) error {
	var recipe rtypes.Policy
	err := proto.Unmarshal([]byte(policy.Recipe), &recipe)
	if err != nil {
		return fmt.Errorf("failed to unmarshal policy recipe: %w", err)
	}
	if recipe.GetSchedule() == nil {
		return nil
	}
	if recipe.GetSchedule().GetStartTime() == nil {
		return s.repo.CreateWithTx(ctx, tx, policy.ID, time.Now())
	}

	startTime := recipe.GetSchedule().GetStartTime().AsTime()

	intervalWrapper, err := NewIntervalSchedule(
		recipe.GetSchedule().GetFrequency(),
		startTime,
		int(recipe.GetSchedule().GetInterval()),
	)
	if err != nil {
		return fmt.Errorf("failed to create schedule: %w", err)
	}

	nextTime := intervalWrapper.Next(time.Now())

	return s.repo.CreateWithTx(ctx, tx, policy.ID, nextTime)
}

func (s *Service) Delete(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error {
	return s.repo.DeleteWithTx(ctx, tx, policyID)
}
