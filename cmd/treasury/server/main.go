package main

import (
	"context"
	"fmt"
	"net"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/scheduler"
	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/verifier/tx_indexer"
	tx_indexer_storage "github.com/vultisig/verifier/tx_indexer/pkg/storage"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/api"
	feeconfig "github.com/vultisig/plugin/cmd/fees/config"
	"github.com/vultisig/plugin/plugin/treasury"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/plugin/storage/postgres"
)

func main() {
	ctx := context.Background()

	cfg, err := feeconfig.GetConfigure()
	if err != nil {
		panic(err)
	}

	logger := logrus.New()
	sdClient, err := statsd.New(net.JoinHostPort(cfg.Datadog.Host, cfg.Datadog.Port))
	if err != nil {
		panic(err)
	}
	redisStorage, err := storage.NewRedisStorage(cfg.Redis)
	if err != nil {
		panic(err)
	}
	redisOptions := asynq.RedisClientOpt{
		Addr:     net.JoinHostPort(cfg.Redis.Host, cfg.Redis.Port),
		Username: cfg.Redis.User,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}

	client := asynq.NewClient(redisOptions)
	defer func() {
		if err := client.Close(); err != nil {
			fmt.Println("fail to close asynq client,", err)
		}
	}()

	inspector := asynq.NewInspector(redisOptions)

	vaultStorage, err := vault.NewBlockStorageImp(cfg.BlockStorage)
	if err != nil {
		panic(err)
	}

	txIndexerStore, err := tx_indexer_storage.NewPostgresTxIndexStore(ctx, cfg.Database.DSN)
	if err != nil {
		panic(fmt.Errorf("tx_indexer_storage.NewPostgresTxIndexStore: %w", err))
	}

	_ = tx_indexer.NewService(
		logger,
		txIndexerStore,
		tx_indexer.Chains(),
	)

	db, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	treasuryPluginConfig, err := treasury.NewTreasuryConfig(
		treasury.WithChainIdRaw(1),
		treasury.WithEthProviderRaw("https://eth.public-rpc.com"),
		treasury.WithEncryptionSecret(cfg.Server.EncryptionSecret))

	if err != nil {
		logger.Fatalf("failed to create treasury config,err: %s", err)
	}

	verifierApi := verifierapi.NewVerifierApi(
		cfg.Verifier.URL,
		cfg.Verifier.Token,
		logger.WithField("pkg", "verifierapi.VerifierApi").Logger,
	)

	treasuryPlugin, err := treasury.NewTreasuryPlugin(
		treasuryPluginConfig,
		vaultStorage,
		nil,
		db,
		logger,
		verifierApi,
	)
	if err != nil {
		logger.Fatalf("failed to create fee plugin,err: %s", err)
	}

	server := api.NewServer(
		cfg.Server,
		db,
		redisStorage,
		vaultStorage,
		client,
		inspector,
		sdClient,
		treasuryPlugin,
		scheduler.NewNilService(),
	)
	if err := server.StartServer(); err != nil {
		panic(err)
	}
}
