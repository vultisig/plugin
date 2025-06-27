package main

import (
	"fmt"
	"net"
	"os"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/plugin/fees"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/plugin/storage/postgres"
	"github.com/vultisig/verifier/vault"
	"github.com/vultisig/verifier/vault_config"
)

//replicates the config created in the cmd/fees/server/config.go

type FeesServerConfig struct {
	Server   api.ServerConfig `mapstructure:"server" json:"server"`
	Database struct {
		DSN string `mapstructure:"dsn" json:"dsn,omitempty"`
	} `mapstructure:"database" json:"database,omitempty"`
	BaseConfigPath string                    `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis          storage.RedisConfig       `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage   vault_config.BlockStorage `mapstructure:"block_storage" json:"block_storage,omitempty"`
	Datadog        struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

func GetConfigure() (*FeesServerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	fmt.Println(configName)

	return ReadConfig(configName)
}

func ReadConfig(configName string) (*FeesServerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("Server.VaultsFilePath", "vaults")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg FeesServerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}

func createDummyServer() (*api.Server, vault.Storage, *fees.FeePlugin) {
	cfg, err := GetConfigure()
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

	fmt.Println(cfg.BlockStorage)

	vaultStorage, err := vault.NewLocalVaultStorage(vault.LocalVaultStorageConfig{
		VaultFilePath: cfg.Server.VaultsFilePath,
	})

	if err != nil {
		panic(err)
	}

	db, err := postgres.NewPostgresBackend(cfg.Database.DSN, nil)
	if err != nil {
		logger.Fatalf("Failed to connect to database: %v", err)
	}

	p := fees.FeePlugin{}

	server := api.NewServer(
		cfg.Server,
		db,
		redisStorage,
		vaultStorage,
		redisOptions,
		client,
		inspector,
		sdClient,
		&p,
	)

	return server, vaultStorage, &p
}
