package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/api"
	"github.com/vultisig/plugin/storage"
)

type DCAServerConfig struct {
	Server         api.ServerConfig         `mapstructure:"server" json:"server"`
	BaseConfigPath string                   `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis          storage.RedisConfig      `mapstructure:"redis" json:"redis,omitempty" mapstructure:"server" json:"redis"`
	BlockStorage   vault.BlockStorageConfig `mapstructure:"block_storage" json:"block_storage,omitempty" mapstructure:"server" json:"block_storage"`
	Datadog        struct {
		Host string `mapstructure:"host" json:"host,omitempty" mapstructure:"server" json:"host"`
		Port string `mapstructure:"port" json:"port,omitempty" mapstructure:"server" json:"port"`
	} `mapstructure:"datadog" json:"datadog" mapstructure:"server" json:"datadog"`
}

func GetConfigure() (*DCAServerConfig, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	return ReadConfig(configName)
}

func ReadConfig(configName string) (*DCAServerConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("Server.VaultsFilePath", "vaults")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg DCAServerConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
