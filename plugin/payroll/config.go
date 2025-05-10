// plugin/payroll/config.go
package payroll

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

type PluginConfig struct {
	Type    string `yaml:"type"`
	Version string `yaml:"version"`
	RpcURL  string `yaml:"rpc_url"`
	Gas     struct {
		LimitMultiplier int `yaml:"limit_multiplier"`
		PriceMultiplier int `yaml:"price_multiplier"`
	} `yaml:"gas"`
	Monitoring struct {
		TimeoutMinutes       int `yaml:"timeout_minutes"`
		CheckIntervalSeconds int `yaml:"check_interval_seconds"`
	} `yaml:"monitoring"`
}

func (c *PluginConfig) Validate() error {
	if c.Type != PLUGIN_TYPE {
		return fmt.Errorf("invalid plugin type: %s", c.Type)
	}
	if c.RpcURL == "" {
		return errors.New("rpc_url is required")
	}
	if c.Gas.LimitMultiplier <= 0 {
		return errors.New("gas limit multiplier must be positive")
	}
	return nil
}

func loadPluginConfig() (*PluginConfig, error) {
	configPath := filepath.Join("plugin", "payroll", "payroll.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config PluginConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}
