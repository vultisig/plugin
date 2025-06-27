package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/vault_config"

	"github.com/vultisig/plugin/storage"
)

type PayrollWorkerConfig struct {
	Redis              storage.RedisConfig       `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage       vault_config.BlockStorage `mapstructure:"block_storage" json:"block_storage,omitempty"`
	VaultServiceConfig vault_config.Config       `mapstructure:"vault_service" json:"vault_service,omitempty"`
	Datadog            struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
	Database struct {
		DSN string `mapstructure:"dsn" json:"dsn,omitempty"`
	} `mapstructure:"database" json:"database,omitempty"`
	BaseConfigPath   string `mapstructure:"base_file_path" json:"base_file_path,omitempty"`
	EncryptionSecret string `mapstructure:"encryption_secret" json:"encryption_secret,omitempty"`
}

func GetConfigure() (*PayrollWorkerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}
	return ReadConfig(configName)
}

func ReadConfig(configName string) (*PayrollWorkerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg PayrollWorkerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
