-- +goose Up
-- +goose StatementBegin
ALTER TABLE plugin_policies
DROP COLUMN IF EXISTS policy;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE plugin_policies
    ADD COLUMN IF NOT EXISTS policy JSONB NOT NULL DEFAULT '{}';
-- +goose StatementEnd
