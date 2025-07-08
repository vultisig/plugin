package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
)

func (p *PostgresBackend) CreateFeeRun(ctx context.Context, policyId uuid.UUID, state types.FeeRunState, fees []verifierapi.FeeDto) (*types.FeeRun, error) {
	// Check policy id is valid
	query := `select plugin_id from plugin_policies where id = $1`
	policyrows := p.pool.QueryRow(ctx, query, policyId)
	var pluginId string
	err := policyrows.Scan(&pluginId)
	if err != nil {
		return nil, err
	}
	if pluginId != "vultisig-fees-feee" {
		return nil, errors.New("plugin id not found or not vultisig-fees-feee")
	}

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	runId := uuid.New()
	_, err = tx.Exec(ctx, `insert into fee_run (id, status, policy_id) values ($1, $2, $3) returning id`, runId, state, policyId)
	if err != nil {
		return nil, fmt.Errorf("failed to insert fee run: %w", err)
	}

	for _, fee := range fees {
		_, err = tx.Exec(ctx, `insert into fee (id, fee_run_id, amount) values ($1, $2, $3)`, fee.ID, runId, fee.Amount)
		if err != nil {
			return nil, fmt.Errorf("failed to insert fee: %s", err)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %s", err)
	}

	var run types.FeeRun
	err = p.pool.QueryRow(ctx, `select id, status, created_at, updated_at, tx_id, policy_id, total_amount, fee_count from fee_run_with_totals where id = $1`, runId).Scan(&run.ID, &run.Status, &run.CreatedAt, &run.UpdatedAt, &run.TxID, &run.PolicyID, &run.TotalAmount, &run.FeeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get fee run (post commit): %s", err)
	}

	return &run, nil
}
