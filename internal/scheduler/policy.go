package scheduler

import (
	"context"

	"github.com/google/uuid"
	"github.com/vultisig/verifier/types"
)

type PolicyFetcher interface {
	GetPluginPolicy(ctx context.Context, id uuid.UUID) (*types.PluginPolicy, error)
}
