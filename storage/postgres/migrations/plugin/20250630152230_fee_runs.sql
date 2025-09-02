-- +goose Up
-- +goose StatementBegin
-- Create fee_run table

CREATE TYPE fee_batch_status as ENUM ('draft', 'sent', 'completed', 'failed');

CREATE TABLE IF NOT EXISTS fee_batch (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id UUID NOT NULL, -- this is the id of the batch credit "fee" on the verifier
    public_key VARCHAR(66) NOT NULL,
    status fee_batch_status NOT NULL DEFAULT 'draft',
    amount BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    tx_hash VARCHAR(66)
);

CREATE TABLE fee_tx (
    hash VARCHAR(66) PRIMARY KEY,
    raw_tx TEXT NOT NULL
);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TABLE IF EXISTS fee_batch;
DROP TYPE IF EXISTS fee_batch_status;
-- +goose StatementEnd

