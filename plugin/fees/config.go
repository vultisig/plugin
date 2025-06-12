package fees

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type PluginConfig struct {
	Type        string `mapstructure:"type"`
	Version     string `mapstructure:"version"`
	RpcURL      string `mapstructure:"rpc_url"`      // URL for the RPC endpoint to interact with the ethereum/evm blockchain
	USDCAddress string `mapstructure:"usdc_address"` // If a non-ethereum chain is used, this is the address of the USDC token contract on that chain
	Gas         struct {
		LimitMultiplier int `mapstructure:"limit_multiplier"`
		PriceMultiplier int `mapstructure:"price_multiplier"`
	} `mapstructure:"gas"`
	Monitoring struct {
		TimeoutMinutes       int `mapstructure:"timeout_minutes"`
		CheckIntervalSeconds int `mapstructure:"check_interval_seconds"`
	} `mapstructure:"monitoring"`
}

func loadPluginConfig(basePath string) (*PluginConfig, error) {
	v := viper.New()
	v.SetConfigName("fees")

	// Add config paths in order of precedence
	if basePath != "" {
		v.AddConfigPath(basePath)
	}
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/vultisig")

	// Enable environment variable overrides
	v.AutomaticEnv()
	v.SetEnvPrefix("FEES")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config PluginConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if config.Type != PLUGIN_TYPE {
		return nil, fmt.Errorf("invalid plugin type: %s", config.Type)
	}
	if config.RpcURL == "" {
		return nil, errors.New("rpc_url is required")
	}
	if config.Gas.LimitMultiplier <= 0 {
		return nil, errors.New("gas limit multiplier must be positive")
	}

	return &config, nil
}
