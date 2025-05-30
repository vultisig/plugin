package postgres

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/common"
)

// SystemMigrationManager handles system-level migrations (plugin_policies table)
type SystemMigrationManager struct {
	pool *pgxpool.Pool
}

func NewSystemMigrationManager(pool *pgxpool.Pool) *SystemMigrationManager {
	return &SystemMigrationManager{pool: pool}
}

func (s *SystemMigrationManager) Migrate() error {
	logrus.Info("Starting system database migration...")
	goose.SetBaseFS(common.SystemMigrations())
	defer goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	db := stdlib.OpenDBFromPool(s.pool)
	defer db.Close()
	if err := goose.Up(db, "migrations/system", goose.WithAllowMissing()); err != nil {
		return fmt.Errorf("failed to run system migrations: %w", err)
	}
	logrus.Info("System database migration completed successfully")
	return nil
}
