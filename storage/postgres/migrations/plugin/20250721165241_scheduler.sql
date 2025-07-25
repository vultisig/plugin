-- +goose Up
-- +goose StatementBegin
BEGIN;
CREATE TABLE IF NOT EXISTS scheduler (
    policy_id UUID PRIMARY KEY,
    next_execution TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scheduler_next_execution ON scheduler(next_execution);
END;
-- +goose StatementEnd
