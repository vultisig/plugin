package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	vtypes "github.com/vultisig/verifier/types"
)

func (p *PostgresBackend) GetPluginPolicy(ctx context.Context, id string) (vtypes.PluginPolicy, error) {
	if p.pool == nil {
		return vtypes.PluginPolicy{}, fmt.Errorf("database pool is nil")
	}

	var policy vtypes.PluginPolicy
	var policyJSON []byte

	query := `
        SELECT id, public_key, plugin_id, plugin_version, policy_version, signature, active, policy, recipe
        FROM plugin_policies 
        WHERE id = $1`

	err := p.pool.QueryRow(ctx, query, id).Scan(
		&policy.ID,
		&policy.PublicKey,
		&policy.PluginID,
		&policy.PluginVersion,
		&policy.PolicyVersion,
		&policy.Signature,
		&policy.Active,
		&policyJSON,
		&policy.Recipe,
	)

	if err != nil {
		return vtypes.PluginPolicy{}, fmt.Errorf("failed to get policy: %w", err)
	}
	policy.Policy = json.RawMessage(policyJSON)

	return policy, nil
}

func (p *PostgresBackend) GetAllPluginPolicies(ctx context.Context, publicKey string, pluginID vtypes.PluginID) ([]vtypes.PluginPolicy, error) {
	if p.pool == nil {
		return []vtypes.PluginPolicy{}, fmt.Errorf("database pool is nil")
	}

	query := `
  	SELECT id, public_key,  plugin_id, plugin_version, policy_version, signature, active, policy, recipe
		FROM plugin_policies
		WHERE public_key = $1
		AND plugin_id = $2`

	rows, err := p.pool.Query(ctx, query, publicKey, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []vtypes.PluginPolicy
	for rows.Next() {
		var policy vtypes.PluginPolicy
		err := rows.Scan(
			&policy.ID,
			&policy.PublicKey,
			&policy.PluginID,
			&policy.PluginVersion,
			&policy.PolicyVersion,
			&policy.Signature,
			&policy.Active,
			&policy.Policy,
			&policy.Recipe,
		)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func (p *PostgresBackend) InsertPluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error) {
	policyJSON, err := json.Marshal(policy.Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	query := `
  	INSERT INTO plugin_policies (
      id, public_key, plugin_id, plugin_version, policy_version, signature, active, policy, recipe
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING id, public_key,  plugin_id, plugin_version, policy_version, signature, active, policy, recipe
	`

	var insertedPolicy vtypes.PluginPolicy
	err = dbTx.QueryRow(ctx, query,
		policy.ID,
		policy.PublicKey,
		policy.PluginID,
		policy.PluginVersion,
		policy.PolicyVersion,
		policy.Signature,
		policy.Active,
		policyJSON,
		policy.Recipe,
	).Scan(
		&insertedPolicy.ID,
		&insertedPolicy.PublicKey,
		&insertedPolicy.PluginID,
		&insertedPolicy.PluginVersion,
		&insertedPolicy.PolicyVersion,
		&insertedPolicy.Signature,
		&insertedPolicy.Active,
		&insertedPolicy.Policy,
		&insertedPolicy.Recipe,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert policy: %w", err)
	}

	return &insertedPolicy, nil
}

func (p *PostgresBackend) UpdatePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, policy vtypes.PluginPolicy) (*vtypes.PluginPolicy, error) {
	policyJSON, err := json.Marshal(policy.Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	query := `
		UPDATE plugin_policies 
		SET plugin_version = $2,
		    policy_version = $3,
			signature = $4,
			active = $5,
			policy = $6,
			recipe = $7
		WHERE id = $1
		RETURNING id, public_key, plugin_id, plugin_version, policy_version, signature, active, policy, recipe
	`

	var updatedPolicy vtypes.PluginPolicy
	err = dbTx.QueryRow(ctx, query,
		policy.ID,
		policy.PluginVersion,
		policy.PolicyVersion,
		policy.Signature,
		policy.Active,
		policyJSON,
		policy.Recipe,
	).Scan(
		&updatedPolicy.ID,
		&updatedPolicy.PublicKey,
		&updatedPolicy.PluginID,
		&updatedPolicy.PluginVersion,
		&updatedPolicy.PolicyVersion,
		&updatedPolicy.Signature,
		&updatedPolicy.Active,
		&updatedPolicy.Policy,
		&updatedPolicy.Recipe,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("policy not found with ID: %s", policy.ID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to update policy: %w", err)
	}

	return &updatedPolicy, nil
}

func (p *PostgresBackend) DeletePluginPolicyTx(ctx context.Context, dbTx pgx.Tx, id string) error {
	_, err := dbTx.Exec(ctx, `
	DELETE FROM transaction_history
	WHERE policy_id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("failed to delete transaction history: %w", err)
	}
	_, err = dbTx.Exec(ctx, `
	DELETE FROM time_triggers
	WHERE policy_id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("failed to delete time triggers: %w", err)
	}
	_, err = dbTx.Exec(ctx, `
	DELETE FROM plugin_policies
	WHERE id = $1
	`, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	return nil
}
