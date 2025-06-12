package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	rtypes "github.com/vultisig/recipes/types"
	vtypes "github.com/vultisig/verifier/types"

	"github.com/vultisig/plugin/internal/types"
)

func TestTimeTrigger(t *testing.T) {
	t.SkipNow()
	// Initialize Postgres backend
	backend, err := NewPostgresBackend("postgres://myuser:mypassword@localhost:5432/vultisig-plugin?sslmode=disable", nil)
	if err != nil {
		t.Fatalf("Failed to create Postgres backend: %v", err)
	}
	defer backend.Close()
	policyID := uuid.New()

	// Create a new time trigger
	trigger := types.TimeTrigger{
		PolicyID:       policyID,
		CronExpression: "0 0 * * *",
		StartTime:      time.Now().UTC(),
		EndTime:        nil,
		Frequency:      rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY,
		Interval:       1,
		Status:         "PENDING",
	}

	ctx := context.Background()
	tx, err := backend.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	if _, err := backend.InsertPluginPolicyTx(ctx, tx, vtypes.PluginPolicy{
		ID:            policyID,
		PublicKey:     "4a7b9c2f8e1d3a5b6c4f9e2d7a1b3c5f8d4e6a2b9c1f7e3d5a6b4c2f8e1d3a5b",
		PluginID:      "vultisig-payroll-0000",
		PluginVersion: "1",
		PolicyVersion: 1,
		Signature:     "whatever",
		Recipe:        "k3uaL47TpWtsT54tfhO7K6Gbyxf4H71jWma0zC2e3kQ=",
		Active:        true,
	}); err != nil {
		tx.Rollback(ctx)
		t.Fatalf("Failed to insert plugin policy: %v", err)
	}
	if err := backend.CreateTimeTriggerTx(ctx, tx, trigger); err != nil {
		tx.Rollback(ctx)
		t.Fatalf("Failed to create time trigger: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	t.Logf("Successfully created time trigger with ID: %s", trigger.PolicyID)

	// Test getting pending time triggers
	triggers, err := backend.GetPendingTimeTriggers(ctx)
	if err != nil {
		t.Fatalf("Failed to get pending time triggers: %v", err)
	}

	if len(triggers) == 0 {
		t.Fatal("Expected at least one pending time trigger")
	}

	t.Logf("Found %d pending time triggers", len(triggers))

	// Test deleting the time trigger
	if err := backend.DeleteTimeTrigger(ctx, trigger.PolicyID); err != nil {
		t.Fatalf("Failed to delete time trigger: %v", err)
	}

	t.Logf("Successfully deleted time trigger with ID: %s", trigger.PolicyID)
}
