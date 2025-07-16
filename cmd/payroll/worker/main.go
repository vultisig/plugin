package main

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/keysign"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/vultiserver/relay"

	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/tasks"
	"github.com/vultisig/plugin/plugin/payroll"
	"github.com/vultisig/plugin/storage/postgres"
)

// Don't scale payroll.worker, it has scheduler which must be single instance running
// Consider moving scheduler to separate worker
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
	client := asynq.NewClient(redisOptions)
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
		client,
		sdClient,
		vaultStorage,
		txIndexerService,
	)
	if err != nil {
		panic(fmt.Errorf("failed to create vault service: %w", err))
	}

	postgressDB, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		panic(fmt.Errorf("failed to create postgres backend: %w", err))
	}

	rpcClient, err := ethclient.Dial(cfg.Rpc.Ethereum.URL)
	if err != nil {
		panic(fmt.Errorf("failed to create eth client: %w", err))
	}

	p, err := payroll.NewPlugin(
		postgressDB,
		keysign.NewSigner(
			logger.WithField("pkg", "keysign.Signer").Logger,
			relay.NewRelayClient(cfg.VaultServiceConfig.Relay.Server),
			[]keysign.Emitter{
				keysign.NewVerifierEmitter(cfg.Verifier.URL, cfg.Verifier.Token),
				keysign.NewPluginEmitter(client, tasks.TypeKeySignDKLS, tasks.QUEUE_NAME),
			},
			[]string{
				cfg.Verifier.PartyPrefix,
				cfg.VaultServiceConfig.LocalPartyPrefix,
			},
		),
		vaultStorage,
		rpcClient,
		txIndexerService,
		client,
		cfg.VaultServiceConfig.EncryptionSecret,
		cfg.VaultServiceConfig.Relay.EncryptionSecret,
	)
	if err != nil {
		panic(fmt.Errorf("failed to create payroll plugin: %w", err))
	}
	schedulerSvc, err := scheduler.NewSchedulerService(postgressDB, client, redisOptions)
	if err != nil {
		panic(fmt.Errorf("failed to create scheduler service: %w", err))
	}

	schedulerSvc.Start()
	defer schedulerSvc.Stop()

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypePluginTransaction, p.HandleSchedulerTrigger)
	mux.HandleFunc(tasks.TypeKeySignDKLS, vaultService.HandleKeySignDKLS)
	mux.HandleFunc(tasks.TypeReshareDKLS, vaultService.HandleReshareDKLS)
	if err := srv.Run(mux); err != nil {
		panic(fmt.Errorf("could not run server: %w", err))
	}
}
