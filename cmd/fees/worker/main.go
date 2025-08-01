package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tasks"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultiserver/relay"

	feeconfig "github.com/vultisig/plugin/cmd/fees/config"
	"github.com/vultisig/plugin/plugin/fees"
	"github.com/vultisig/plugin/storage/postgres"
)

func startLoadingFees(asynqClient *asynq.Client, logger *logrus.Logger) {
	logger.Info("Loading fees")
	payload, err := json.Marshal(fees.FeeCollectionFormat{
		FeeCollectionType: fees.FeeCollectionTypeAll,
	})
	if err != nil {
		logger.WithError(err).Error("Failed to marshal fee loading config in demo run")
		return
	}
	asynqClient.Enqueue(
		asynq.NewTask(fees.TypeFeeLoad, payload),
		asynq.MaxRetry(0),
		asynq.Timeout(2*time.Minute),
		asynq.Retention(5*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
}

func startTransactingFees(asynqClient *asynq.Client, logger *logrus.Logger) {
	logger.Info("Transacting fees")
	payload := make([]byte, 0)
	asynqClient.Enqueue(
		asynq.NewTask(fees.TypeFeeTransact, payload),
		asynq.MaxRetry(0),
		asynq.Timeout(2*time.Minute),
		asynq.Retention(5*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
}

func startPostTx(asynqClient *asynq.Client, logger *logrus.Logger) {
	logger.Info("Checking status")
	payload := make([]byte, 0)
	asynqClient.Enqueue(
		asynq.NewTask(fees.TypeFeePostTx, payload),
		asynq.MaxRetry(0),
		asynq.Timeout(2*time.Minute),
		asynq.Retention(5*time.Minute),
		asynq.Queue(tasks.QUEUE_NAME))
}

func main() {
	ctx := context.Background()

	cfg, err := feeconfig.GetConfigure()
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
				tasks.QUEUE_NAME: 10,
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

	signer := keysign.NewSigner(
		logger.WithField("pkg", "keysign.Signer").Logger,
		relay.NewRelayClient(cfg.VaultServiceConfig.Relay.Server),
		[]keysign.Emitter{
			keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.Token),
			keysign.NewPluginEmitter(asynqClient, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
		},
		[]string{
			cfg.Verifier.PartyPrefix,
			cfg.VaultServiceConfig.LocalPartyPrefix,
		},
	)

	feePlugin, err := fees.NewFeePlugin(
		postgressDB,
		signer,
		logger,
		cfg.BaseConfigPath,
		vaultStorage,
		txIndexerService,
		asynqInspector,
		asynqClient,
		feePluginConfig,
		cfg.VaultServiceConfig.EncryptionSecret,
		cfg.Verifier.URL,
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
	mux.HandleFunc(fees.TypeFeeLoad, feePlugin.LoadFees)
	mux.HandleFunc(fees.TypeFeeTransact, feePlugin.HandleTransactions)
	mux.HandleFunc(fees.TypeFeePostTx, feePlugin.HandlePostTx)

	// Load fees every 10 minutes
	loadFees := cron.New()
	loadFees.AddFunc(feePluginConfig.Jobs.Load.Cronexpr, func() {
		startLoadingFees(asynqClient, logger)
	})
	loadFees.Start()

	// Transact fees every Friday at 12:00 PM
	transactFees := cron.New()
	transactFees.AddFunc(feePluginConfig.Jobs.Transact.Cronexpr, func() {
		startTransactingFees(asynqClient, logger)
	})
	transactFees.Start()

	// // Update verifier every 10 minutes
	updateVerifier := cron.New()
	updateVerifier.AddFunc(feePluginConfig.Jobs.Post.Cronexpr, func() {
		startPostTx(asynqClient, logger)
	})
	updateVerifier.Start()

	logger.Info("Starting asynq listener")

	if err := srv.Run(mux); err != nil {
		panic(fmt.Errorf("could not run server: %w", err))
	}
}
