package scheduler

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/vultisig/verifier/types"
)

// NilService implements the scheduler.Service for plugins where scheduling not required
type NilService struct{}

func NewNilService() *NilService {
	return &NilService{}
}

func (s *NilService) FromNowWhenNext(_ types.PluginPolicy) (time.Time, error) {
	return time.Time{}, nil
}

func (s *NilService) Create(_ context.Context, _ pgx.Tx, _ types.PluginPolicy) error {
	return nil
}

func (s *NilService) Update(_ context.Context, _ pgx.Tx, _, _ types.PluginPolicy) error {
	return nil
}

func (s *NilService) Delete(_ context.Context, _ pgx.Tx, _ uuid.UUID) error {
	return nil
}
