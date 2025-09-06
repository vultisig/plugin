package treasury

import (
	"context"

	"github.com/hibiken/asynq"
)

func (tp *TreasuryPlugin) TransactTreasuryPayments(ctx context.Context, t *asynq.Task) error {
	tp.logger.Info("Transacting treasury payments")
	return nil
}
