package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/vultisig/plugin/internal/types"
)

// checkContext returns ctx.Err() if the context is done (timeout or canceled), otherwise nil.
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("context is nil")
	}
	return ctx.Err()
}

func (p *PostgresBackend) CreateTimeTriggerTx(ctx context.Context, tx pgx.Tx, trigger types.TimeTrigger) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	query := `
		INSERT INTO time_triggers 
    (policy_id, cron_expression, start_time, end_time, frequency, interval, status) 
    VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := tx.Exec(ctx, query,
		trigger.PolicyID,
		trigger.CronExpression,
		trigger.StartTime,
		trigger.EndTime,
		trigger.Frequency,
		trigger.Interval,
		trigger.Status,
	)

	return err
}

func (p *PostgresBackend) DeleteTimeTrigger(ctx context.Context, policyID uuid.UUID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	query := `DELETE FROM time_triggers WHERE policy_id = $1`
	_, err := p.pool.Exec(ctx, query, policyID)

	return err
}

func (p *PostgresBackend) GetPendingTimeTriggers(ctx context.Context) ([]types.TimeTrigger, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	// TODO: add limit and proper index
	query := `
  	WITH active_triggers AS (
   		SELECT t.policy_id, t.cron_expression, t.start_time, t.end_time, t.frequency, t.interval, t.last_execution, t.status
				FROM time_triggers t
				INNER JOIN plugin_policies p ON t.policy_id = p.id
				WHERE t.start_time <= $1
				AND (t.end_time IS NULL OR t.end_time > $1)
				AND p.active = true
				AND t.status = 'PENDING'
				AND (t.last_execution IS NULL OR t.last_execution < $1)
    )
    SELECT * FROM active_triggers
    ORDER BY start_time ASC
	`

	rows, err := p.pool.Query(ctx, query, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var triggers []types.TimeTrigger
	for rows.Next() {
		var t types.TimeTrigger
		err := rows.Scan(
			&t.PolicyID,
			&t.CronExpression,
			&t.StartTime,
			&t.EndTime,
			&t.Frequency,
			&t.Interval,
			&t.LastExecution,
			&t.Status)
		if err != nil {
			return nil, err
		}
		triggers = append(triggers, t)
	}

	return triggers, nil
}

func (p *PostgresBackend) UpdateTimeTriggerLastExecution(ctx context.Context, policyID uuid.UUID) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	query := `
		UPDATE time_triggers 
		SET last_execution = $2
		WHERE policy_id = $1
	`

	_, err := p.pool.Exec(ctx, query, policyID, time.Now().UTC())
	return err
}

func (p *PostgresBackend) UpdateTimeTriggerTx(ctx context.Context, policyID uuid.UUID, trigger types.TimeTrigger, tx pgx.Tx) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	query := `
		UPDATE time_triggers
		SET start_time = $2,
				frequency = $3,
				interval = $4,
				cron_expression = $5
		WHERE policy_id = $1
	`
	_, err := tx.Exec(ctx, query,
		policyID,
		trigger.StartTime,
		trigger.Frequency,
		trigger.Interval,
		trigger.CronExpression,
	)
	return err
}

func (p *PostgresBackend) GetTriggerStatus(ctx context.Context, policyID uuid.UUID) (types.TimeTriggerStatus, error) {
	if err := checkContext(ctx); err != nil {
		return "", err
	}

	query := `
		SELECT status 
		FROM time_triggers 
		WHERE policy_id = $1
	`

	var status types.TimeTriggerStatus
	err := p.pool.QueryRow(ctx, query, policyID).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("trigger not found for policy_id: %s", policyID)
		}
		return "", err
	}

	return status, nil
}

func (p *PostgresBackend) UpdateTriggerStatus(ctx context.Context, policyID uuid.UUID, status types.TimeTriggerStatus) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	query := `
		UPDATE time_triggers 
		SET status = $2
		WHERE policy_id = $1
	`

	_, err := p.pool.Exec(ctx, query, policyID, status)
	return err
}
