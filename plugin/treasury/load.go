package treasury

import (
	"context"

	"github.com/hibiken/asynq"
)

func (tp *TreasuryPlugin) LoadTreasuryPayments(ctx context.Context, t *asynq.Task) error {
	tp.logger.Info("Loading treasury payments")
	return nil
}
