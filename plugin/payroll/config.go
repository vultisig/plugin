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

func loadPluginConfig(basePath string) (*PluginConfig, error) {

	if basePath != "" {
		configPath := filepath.Join(basePath, "payroll.yml")
		if data, err := os.ReadFile(configPath); err == nil {
			return parseConfig(data)
		}
	}

	// Fallback to default system path
	configPath := filepath.Join("/etc/vultisig", "payroll.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return parseConfig(data)
}

func parseConfig(data []byte) (*PluginConfig, error) {
	var config PluginConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

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
