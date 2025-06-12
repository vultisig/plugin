package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/vault_config"

	"github.com/vultisig/plugin/storage"
)

type DCAWorkerConfig struct {
	Database struct {
		DSN string `mapstructure:"dsn" json:"dsn,omitempty"`
	} `mapstructure:"database" json:"database,omitempty"`
	Redis              storage.RedisConfig             `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage       vault_config.BlockStorageConfig `mapstructure:"block_storage" json:"block_storage,omitempty"`
	VaultServiceConfig vault_config.Config             `mapstructure:"vault_service" json:"vault_service,omitempty"`
	Datadog            struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

func GetConfigure() (*DCAWorkerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	return ReadConfig(configName)
}

func ReadConfig(configName string) (*DCAWorkerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg DCAWorkerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
