package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/storage"
)

type PayrollServerConfig struct {
	Server         api.ServerConfig         `mapstructure:"server" json:"server"`
	BaseConfigPath string                   `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis          storage.RedisConfig      `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage   vault.BlockStorageConfig `mapstructure:"block_storage" json:"block_storage,omitempty"`
	Datadog        struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

func GetConfigure() (*PayrollServerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	return ReadConfig(configName)
}

func ReadConfig(configName string) (*PayrollServerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("Server.VaultsFilePath", "vaults")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file, %w", err)
	}
	var cfg PayrollServerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
