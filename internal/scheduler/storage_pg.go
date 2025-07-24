package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStorage struct {
	pool *pgxpool.Pool
}

func NewPostgresStorage(pool *pgxpool.Pool) *PostgresStorage {
	return &PostgresStorage{
		pool: pool,
	}
}

func (s *PostgresStorage) CreateWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID, next time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO scheduler (policy_id, next_execution)
		VALUES ($1, $2)
	`, policyID, next)
	if err != nil {
		return fmt.Errorf("failed to create scheduler entry: %w", err)
	}
	return nil
}

func (s *PostgresStorage) GetByPolicy(ctx context.Context, policyID uuid.UUID) (Scheduler, error) {
	var scheduler Scheduler
	err := s.pool.QueryRow(ctx, `
		SELECT policy_id, next_execution
		FROM scheduler
		WHERE policy_id = $1
		LIMIT 1
	`, policyID).Scan(&scheduler.PolicyID, &scheduler.NextExecution)
	if err != nil {
		return Scheduler{}, fmt.Errorf("failed to query scheduler by policy: %w", err)
	}

	return scheduler, nil
}

func (s *PostgresStorage) GetPending(ctx context.Context) ([]Scheduler, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT policy_id, next_execution
		FROM scheduler
		WHERE next_execution <= NOW()
		ORDER BY next_execution
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending scheduler entries: %w", err)
	}
	defer rows.Close()

	var schedulers []Scheduler
	for rows.Next() {
		var scheduler Scheduler
		if err := rows.Scan(&scheduler.PolicyID, &scheduler.NextExecution); err != nil {
			return nil, fmt.Errorf("failed to scan scheduler entry: %w", err)
		}
		schedulers = append(schedulers, scheduler)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over scheduler entries: %w", err)
	}

	return schedulers, nil
}

func (s *PostgresStorage) SetNext(ctx context.Context, policyID uuid.UUID, next time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE scheduler
		SET next_execution = $2
		WHERE policy_id = $1
	`, policyID, next)
	if err != nil {
		return fmt.Errorf("failed to update next execution time: %w", err)
	}
	return nil
}

func (s *PostgresStorage) SetNextWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID, next time.Time) error {
	_, err := tx.Exec(ctx, `
		UPDATE scheduler
		SET next_execution = $2
		WHERE policy_id = $1
	`, policyID, next)
	if err != nil {
		return fmt.Errorf("failed to update next execution time: %w", err)
	}
	return nil
}

func (s *PostgresStorage) DeleteWithTx(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM scheduler
		WHERE policy_id = $1
	`, policyID)
	if err != nil {
		return fmt.Errorf("failed to delete scheduler entry: %w", err)
	}
	return nil
}
