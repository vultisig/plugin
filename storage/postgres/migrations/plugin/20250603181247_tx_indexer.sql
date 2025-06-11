-- +goose Up
-- +goose StatementBegin
BEGIN;
CREATE TYPE tx_indexer_status AS ENUM ('PROPOSED', 'VERIFIED', 'SIGNED');

CREATE TYPE tx_indexer_status_onchain AS ENUM ('PENDING', 'SUCCESS', 'FAIL');

CREATE TABLE tx_indexer (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plugin_id VARCHAR(255) NOT NULL,
    tx_hash VARCHAR(255),
    chain_id INTEGER NOT NULL,
    policy_id UUID NOT NULL,
    from_public_key VARCHAR(255) NOT NULL,
    proposed_tx_hex TEXT NOT NULL,

    status tx_indexer_status NOT NULL DEFAULT 'PROPOSED',
    status_onchain tx_indexer_status_onchain,

    -- is Tx stuck in status_onchain=PENDING more than configured timeout,
    -- flag to exclude it from on-chain status polling
    lost BOOLEAN NOT NULL DEFAULT false,
    -- when signed tx broadcasted on-chain
    broadcasted_at TIMESTAMP,
    -- to reindex something: set lost=false and broadcasted_at=now()

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_tx_indexer_status_onchain_lost ON tx_indexer(status_onchain, lost);
END;
-- +goose StatementEnd
