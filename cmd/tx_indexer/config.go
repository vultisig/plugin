package main

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/verifier/tx_indexer/pkg/config"
)

func GetConfigure() (*config.Config, error) {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	return ReadConfig(configName)
}

func ReadConfig(configName string) (*config.Config, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file, %w", err)
	}
	var cfg config.Config
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}
