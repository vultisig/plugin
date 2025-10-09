package postgres

import (
	"embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/sirupsen/logrus"
)

//go:embed migrations/plugin/*.sql
var pluginMigrations embed.FS

// PluginMigrationManager handles plugin-specific migrations
type PluginMigrationManager struct {
	pool *pgxpool.Pool
}

func NewPluginMigrationManager(pool *pgxpool.Pool) *PluginMigrationManager {
	return &PluginMigrationManager{pool: pool}
}

func (v *PluginMigrationManager) Migrate() error {
	logrus.Info("Starting plugin database migration...")
	goose.SetBaseFS(pluginMigrations)
	defer goose.SetBaseFS(nil)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	db := stdlib.OpenDBFromPool(v.pool)
	defer db.Close()
	if err := goose.Up(db, "migrations/plugin", goose.WithAllowMissing()); err != nil {
		return fmt.Errorf("failed to run plugin migrations: %w", err)
	}
	logrus.Info("Plugin database migration completed successfully")
	return nil
}
