package main

import (
	"context"
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/plugin/plugin/fees"
	"github.com/vultisig/plugin/storage/postgres"
)

func main() {
	ctx := context.Background()

	cfg, err := GetConfigure()
	if err != nil {
		panic(err)
	}

	sdClient, err := statsd.New(cfg.Datadog.Host + ":" + cfg.Datadog.Port)
	if err != nil {
		panic(err)
	}
	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize vault storage: %v", err))
	}

	redisOptions := asynq.RedisClientOpt{
		Addr:     cfg.Redis.Host + ":" + cfg.Redis.Port,
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	logger := logrus.StandardLogger()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
	})
	asynqClient := asynq.NewClient(redisOptions)
	asynqInspector := asynq.NewInspector(redisOptions)

	srv := asynq.NewServer(
		redisOptions,
		asynq.Config{
			Logger:      logger,
			Concurrency: 10,
			Queues: map[string]int{
				tasks.QUEUE_NAME:         10,
				"scheduled_plugin_queue": 10, // new queue
			},
		},
	)

	postgressDB, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		panic(fmt.Errorf("failed to create postgres backend: %w", err))
	}

	txIndexerStore, err := storage.NewPostgresTxIndexStore(ctx, cfg.Database.DSN)
	if err != nil {
		panic(fmt.Errorf("storage.NewPostgresTxIndexStore: %w", err))
	}

	txIndexerService := tx_indexer.NewService(
		logger,
		txIndexerStore,
		tx_indexer.Chains(),
	)

	vaultService, err := vault.NewManagementService(
		cfg.VaultServiceConfig,
		asynqClient,
		sdClient,
		vaultStorage,
		txIndexerService,
	)
	if err != nil {
		panic(fmt.Errorf("failed to create vault service: %w", err))
	}

	feePluginConfig, err := fees.NewFeeConfig(fees.WithFileConfig(cfg.BaseConfigPath))
	if err != nil {
		logger.Fatalf("failed to create fees config,err: %s", err)
	}

	feePlugin, err := fees.NewFeePlugin(
		postgressDB,
		logger,
		cfg.BaseConfigPath,
		vaultStorage,
		txIndexerService,
		asynqInspector,
		asynqClient,
		feePluginConfig,
		cfg.VaultServiceConfig.EncryptionSecret,
		cfg.Server.VerifierUrl,
	)
	if err != nil {
		logger.Fatalf("failed to create fee plugin,err: %s", err)
	}

	mux := asynq.NewServeMux()
	//	mux.HandleFunc(tasks.TypePluginTransaction, vaultService.HandlePluginTransaction)

	//Core functions, every plugin should have these functions
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)

	//Plugin specific functions.
	mux.HandleFunc(fees.TypeFeeCollection, feePlugin.HandleCollections)

	logger.Info("Starting asynq listener")
	if err := srv.Run(mux); err != nil {
		panic(fmt.Errorf("could not run server: %w", err))
	}
}
