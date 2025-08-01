package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"
	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
)

func (p *PostgresBackend) CreateFeeRun(ctx context.Context, policyId uuid.UUID, state types.FeeRunState, fees ...verifierapi.FeeDto) (*types.FeeRun, error) {
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
			return nil, fmt.Errorf("failed to insert fee: %w", err)
		}
	}

	err = tx.Commit(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	var run types.FeeRun
	err = p.pool.QueryRow(ctx, `select id, status, created_at, updated_at, tx_hash, policy_id, total_amount, fee_count from fee_run_with_totals where id = $1`, runId).Scan(&run.ID, &run.Status, &run.CreatedAt, &run.UpdatedAt, &run.TxHash, &run.PolicyID, &run.TotalAmount, &run.FeeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get fee run (post commit): %s", err)
	}

	return &run, nil
}

func (p *PostgresBackend) SetFeeRunSent(ctx context.Context, runId uuid.UUID, txHash string) error {
	_, err := p.pool.Exec(ctx, `update fee_run set status = $1, tx_hash = $2 where id = $3`, types.FeeRunStateSent, txHash, runId)
	if err != nil {
		return fmt.Errorf("failed to update fee run: %w", err)
	}
	return nil
}

func (p *PostgresBackend) SetFeeRunSuccess(ctx context.Context, runId uuid.UUID) error {
	_, err := p.pool.Exec(ctx, `update fee_run set status = $1 where id = $2`, types.FeeRunStateSuccess, runId)
	if err != nil {
		return fmt.Errorf("failed to update fee run: %w", err)
	}
	return nil
}

func (p *PostgresBackend) GetAllFeeRuns(ctx context.Context, statuses ...types.FeeRunState) ([]types.FeeRun, error) {

	var rows pgx.Rows
	var err error

	if len(statuses) == 0 {
		query := `select id, status, created_at, updated_at, tx_hash, policy_id, total_amount, fee_count from fee_run_with_totals`
		rows, err = p.pool.Query(ctx, query)
	} else {
		query := `select id, status, created_at, updated_at, tx_hash, policy_id, total_amount, fee_count from fee_run_with_totals where status = ANY($1)`
		rows, err = p.pool.Query(ctx, query, statuses)
	}

	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rm := make(map[uuid.UUID]types.FeeRun)
	for rows.Next() {
		var run types.FeeRun
		err := rows.Scan(&run.ID, &run.Status, &run.CreatedAt, &run.UpdatedAt, &run.TxHash, &run.PolicyID, &run.TotalAmount, &run.FeeCount)
		if err != nil {
			return nil, err
		}
		rm[run.ID] = run
	}

	runIds := make([]uuid.UUID, 0, len(rm))
	for runId := range rm {
		runIds = append(runIds, runId)
	}

	feesQuery := `select id, fee_run_id, amount from fee where fee_run_id = ANY($1)`
	feesRows, err := p.pool.Query(ctx, feesQuery, runIds)
	if err != nil {
		return nil, err
	}
	defer feesRows.Close()
	for feesRows.Next() {
		var fee types.Fee
		err := feesRows.Scan(&fee.ID, &fee.FeeRunID, &fee.Amount)
		if err != nil {
			return nil, err
		}
		if run, ok := rm[fee.FeeRunID]; !ok {
			return nil, fmt.Errorf("fee run not found: %s", fee.FeeRunID)
		} else {
			run.Fees = append(run.Fees, fee)
			rm[fee.FeeRunID] = run
		}
	}

	runs := make([]types.FeeRun, 0, len(rm))
	for _, run := range rm {
		runs = append(runs, run)
	}
	return runs, nil
}

func (p *PostgresBackend) GetFees(ctx context.Context, feeIds ...uuid.UUID) ([]types.Fee, error) {
	query := `select id, fee_run_id, amount from fee where id = ANY($1)`
	rows, err := p.pool.Query(ctx, query, feeIds)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	fees := []types.Fee{}
	for rows.Next() {
		var fee types.Fee
		err := rows.Scan(&fee.ID, &fee.FeeRunID, &fee.Amount)
		if err != nil {
			return nil, err
		}
		fees = append(fees, fee)
	}
	return fees, nil
}

func (p *PostgresBackend) GetPendingFeeRun(ctx context.Context, policyId uuid.UUID) (*types.FeeRun, error) {
	query := `select id, status, created_at, updated_at, tx_hash, policy_id, total_amount, fee_count from fee_run_with_totals where status = $1 and policy_id = $2 order by created_at desc limit 1`
	rows, err := p.pool.Query(ctx, query, types.FeeRunStateDraft, policyId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, nil
	}
	var run types.FeeRun
	err = rows.Scan(&run.ID, &run.Status, &run.CreatedAt, &run.UpdatedAt, &run.TxHash, &run.PolicyID, &run.TotalAmount, &run.FeeCount)
	if err != nil {
		return nil, err
	}
	return &run, nil
}

func (p *PostgresBackend) CreateFee(ctx context.Context, runId uuid.UUID, fee verifierapi.FeeDto) error {
	_, err := p.pool.Exec(ctx, `insert into fee (id, fee_run_id, amount) values ($1, $2, $3)`, fee.ID, runId, fee.Amount)
	if err != nil {
		return fmt.Errorf("failed to insert fee: %w", err)
	}
	return nil
}

func (p *PostgresBackend) GetFeeRuns(ctx context.Context, state types.FeeRunState) ([]types.FeeRun, error) {
	query := `select id, status, created_at, updated_at, tx_hash, policy_id, total_amount, fee_count from fee_run_with_totals where status = $1`
	rows, err := p.pool.Query(ctx, query, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	runs := []types.FeeRun{}

	for rows.Next() {
		var run types.FeeRun
		err := rows.Scan(&run.ID, &run.Status, &run.CreatedAt, &run.UpdatedAt, &run.TxHash, &run.PolicyID, &run.TotalAmount, &run.FeeCount)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	return runs, nil
}
