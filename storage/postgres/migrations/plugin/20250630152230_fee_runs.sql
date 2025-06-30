-- +goose Up
-- +goose StatementBegin
-- Create fee_run table
CREATE TABLE IF NOT EXISTS fee_run (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(50) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'sent', 'completed', 'failed')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    tx_id UUID REFERENCES tx_indexer(id) ON DELETE SET NULL,
    policy_id UUID NOT NULL REFERENCES plugin_policies(id) ON DELETE CASCADE
);

-- Create fee table
CREATE TABLE IF NOT EXISTS fee (
    id UUID PRIMARY KEY,
    fee_run_id UUID NOT NULL REFERENCES fee_run(id) ON DELETE CASCADE,
    amount INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(id, fee_run_id)
);

-- Create view for fee runs with total amounts
CREATE OR REPLACE VIEW fee_run_with_totals AS
SELECT 
    fr.id,
    fr.status,
    fr.created_at,
    fr.updated_at,
    fr.tx_id,
    fr.policy_id,
    COALESCE(SUM(fi.amount), 0) as total_amount,
    COUNT(fi.id) as fee_count
FROM fee_run fr
LEFT JOIN fee fi ON fr.id = fi.fee_run_id
GROUP BY fr.id, fr.status, fr.created_at, fr.updated_at, fr.tx_id, fr.policy_id;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_fee_run_status ON fee_run(status);
CREATE INDEX IF NOT EXISTS idx_fee_run_created_at ON fee_run(created_at);
CREATE INDEX IF NOT EXISTS idx_fee_id_fee_run_id ON fee(fee_run_id);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_fee_run_updated_at 
    BEFORE UPDATE ON fee_run 
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Drop trigger first
DROP TRIGGER IF EXISTS update_fee_run_updated_at ON fee_run;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_fee_id_fee_run_id;
DROP INDEX IF EXISTS idx_fee_run_created_at;
DROP INDEX IF EXISTS idx_fee_run_status;

-- Drop view
DROP VIEW IF EXISTS fee_run_with_totals;

-- Drop tables (in reverse order due to foreign key constraints)
DROP TABLE IF EXISTS fee;
DROP TABLE IF EXISTS fee_run;
-- +goose StatementEnd
