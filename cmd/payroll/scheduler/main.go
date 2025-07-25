package main

import (
	"fmt"
	"net"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/plugin/plugin/payroll"
	"github.com/vultisig/plugin/storage/postgres"
)

func main() {
	cfg, err := GetConfigure()
	if err != nil {
		panic(fmt.Errorf("failed to get config: %w", err))
	}

	client := asynq.NewClient(asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})
	defer func() {
		_ = client.Close()
	}()

	db, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		panic(fmt.Errorf("failed to create db conn: %w", err))
	}

	worker := scheduler.NewWorker(
		logrus.New(),
		client,
		tasks.TypePluginTransaction,
		tasks.QUEUE_NAME,
		scheduler.NewPostgresStorage(db.Pool()),
		payroll.NewSchedulerInterval(),
		db,
	)

	err = worker.Run()
	if err != nil {
		panic(fmt.Errorf("failed to run worker: %w", err))
	}
}
