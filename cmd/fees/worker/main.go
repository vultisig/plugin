package main

import (
	"context"
	"encoding/json"
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
	asynqClient := asynq.NewClient(redisOptions)

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

	feePluginConfig, err := fees.NewFeeConfig(fees.WithVerifierUrl(cfg.Server.VerifierUrl))
	if err != nil {
		logger.Fatalf("failed to create fees config,err: %s", err)
	}

	feePlugin, err := fees.NewFeePlugin(postgressDB, logger, cfg.BaseConfigPath, feePluginConfig)
	if err != nil {
		logger.Fatalf("failed to create DCA plugin,err: %s", err)
	}

	mux := asynq.NewServeMux()
	//	mux.HandleFunc(tasks.TypePluginTransaction, vaultService.HandlePluginTransaction)

	//Core functions, every plugin should have these functions
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)

	//Plugin specific functions.
	mux.HandleFunc(fees.TypeFeeCollection, feePlugin.HandleCollections)

	//Simulate a fee collection run
	//TODO garry. This is purely for e2e testing. Remove from prod.
	go func() {
		logger.Info("Simulating a fee collection run, waiting 0.5 seconds")

		time.Sleep(500 * time.Millisecond)
		logger.Info("Enqueueing Task")

		payload, err := json.Marshal(fees.FeeCollectionFormat{
			FeeCollectionType: fees.FeeCollectionTypeByPolicy,
			Value:             "00000000-0000-0000-0000-000000000001",
		})

		if err != nil {
			logger.WithError(err).Error("Failed to marshal fee collection config in demo run")
			return
		}

		if err != nil {
			logger.WithError(err).Error("Failed to marshal fee collection config")
			return
		}

		asynqClient.Enqueue(
			asynq.NewTask(fees.TypeFeeCollection, payload),
			asynq.MaxRetry(0),
			asynq.Timeout(2*time.Minute),
			asynq.Retention(5*time.Minute),
			asynq.Queue(tasks.QUEUE_NAME))
	}()

	logger.Info("Starting asynq listener")
	if err := srv.Run(mux); err != nil {
		panic(fmt.Errorf("could not run server: %w", err))
	}
}
