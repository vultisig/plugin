package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/vultisig/plugin/internal/types"
)

func (p *PostgresBackend) CreateFeeBatch(ctx context.Context, tx pgx.Tx, batches ...types.FeeBatch) ([]types.FeeBatch, error) {
	query := `insert into fee_batch (id, batch_id, public_key, status, amount, tx_hash) values ($1, $2, $3, $4, $5, $6) returning *`
	feeBatches := make([]types.FeeBatch, 0, len(batches))
	for _, batch := range batches {
		rows, err := tx.Query(ctx, query, batch.ID, batch.BatchID, batch.PublicKey, batch.Status, batch.Amount, batch.TxHash)
		if err != nil {
			return nil, err
		}

		insertedBatch, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[types.FeeBatch])
		if err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()

		feeBatches = append(feeBatches, insertedBatch)
	}

	return feeBatches, nil
}

func (p *PostgresBackend) SetFeeBatchStatus(ctx context.Context, tx pgx.Tx, batchId uuid.UUID, status types.FeeBatchState) error {
	query := `update fee_batch set status = $1 where batch_id = $2`
	_, err := tx.Exec(ctx, query, status, batchId)
	if err != nil {
		return err
	}
	return nil
}

func (p *PostgresBackend) GetFeeBatch(ctx context.Context, batchIDs ...uuid.UUID) ([]types.FeeBatch, error) {

	query := `select * from fee_batch where batch_id = ANY($1)`
	rows, err := p.pool.Query(ctx, query, batchIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	feeBatches := make([]types.FeeBatch, 0, len(batchIDs))
	for rows.Next() {
		feebatch, err := pgx.RowToStructByName[types.FeeBatch](rows)
		if err != nil {
			return nil, err
		}
		feeBatches = append(feeBatches, feebatch)
	}
	return feeBatches, nil
}

func (p *PostgresBackend) GetFeeBatchByStatus(ctx context.Context, status types.FeeBatchState) ([]types.FeeBatch, error) {
	query := `select * from fee_batch where status = $1`
	rows, err := p.pool.Query(ctx, query, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	feeBatches := []types.FeeBatch{}
	for rows.Next() {
		feebatch, err := pgx.RowToStructByName[types.FeeBatch](rows)
		if err != nil {
			return nil, err
		}
		feeBatches = append(feeBatches, feebatch)
	}
	return feeBatches, nil
}

func (p *PostgresBackend) SetFeeBatchSent(ctx context.Context, tx pgx.Tx, txHash string, batchId uuid.UUID) error {
	query := `update fee_batch set status = $1, tx_hash = $2 where batch_id = $3`
	_, err := tx.Exec(ctx, query, types.FeeBatchStateSent, txHash, batchId)
	return err
}
