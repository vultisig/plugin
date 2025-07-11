package payroll

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type PluginConfig struct {
	Type     string   `mapstructure:"type"`
	Version  string   `mapstructure:"version"`
	Rpc      rpc      `mapstructure:"rpc"`
	Verifier verifier `mapstructure:"verifier"`
}

type rpc struct {
	Ethereum rpcItem `mapstructure:"ethereum"`
}

type rpcItem struct {
	URL string `mapstructure:"url"`
}

type verifier struct {
	URL   string `mapstructure:"url"`
	Token string `mapstructure:"token"`
}

func loadPluginConfig(basePath string) (*PluginConfig, error) {
	v := viper.New()
	v.SetConfigName("payroll")

	// Add config paths in order of precedence
	if basePath != "" {
		v.AddConfigPath(basePath)
	}
	v.AddConfigPath(".")
	v.AddConfigPath("/etc/vultisig")

	// Enable environment variable overrides
	v.AutomaticEnv()
	v.SetEnvPrefix("PAYROLL")
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

	return &config, nil
}
