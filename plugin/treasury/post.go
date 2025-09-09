package treasury

import (
	"context"

	"github.com/hibiken/asynq"
)

func (tp *TreasuryPlugin) PostTreasuryPayments(ctx context.Context, t *asynq.Task) error {
	tp.logger.Info("Posting treasury payments")
	return nil
}
