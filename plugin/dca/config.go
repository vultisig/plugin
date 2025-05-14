// plugin/dca/config.go
package dca

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type PluginConfig struct {
	Type    string `mapstructure:"type"`
	Version string `mapstructure:"version"`
	RpcURL  string `mapstructure:"rpc_url"`
	Uniswap struct {
		V2Router string `mapstructure:"v2_router"`
		Deadline int64  `mapstructure:"deadline"`
	} `mapstructure:"uniswap"`
}

func loadPluginConfig(basePath string) (*PluginConfig, error) {
	v := viper.New()
	v.SetConfigName("dca")

	// Add config paths in order of precedence
	if basePath != "" {
		v.AddConfigPath(basePath)
	}
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/vultisig")

	// Enable environment variable overrides
	v.AutomaticEnv()
	v.SetEnvPrefix("DCA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config PluginConfig
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if config.RpcURL == "" {
		return nil, errors.New("rpc_url is required")
	}
	if config.Uniswap.V2Router == "" {
		return nil, errors.New("uniswap v2 router address is required")
	}
	if config.Uniswap.Deadline <= 0 {
		return nil, errors.New("uniswap deadline must be positive")
	}

	return &config, nil
}
