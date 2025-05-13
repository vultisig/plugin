// plugin/dca/config.go
package dca

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
	Uniswap struct {
		V2Router string `yaml:"v2_router"`
		Deadline int64  `yaml:"deadline"`
	} `yaml:"uniswap"`
}

func loadPluginConfig(basePath string) (*PluginConfig, error) {
	// First try the base path from config
	if basePath != "" {
		configPath := filepath.Join(basePath, "dca.yml")
		if data, err := os.ReadFile(configPath); err == nil {
			return parseConfig(data)
		}
	}

	// Fallback to default system path
	configPath := filepath.Join("/etc/vultisig", "dca.yml")
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

	// Validate configuration
	if config.RpcURL == "" {
		return nil, errors.New("rpc_url is required")
	}
	if config.Uniswap.V2Router == "" {
		return nil, errors.New("uniswap.v2_router is required")
	}
	if config.Uniswap.Deadline <= 0 {
		return nil, errors.New("uniswap.deadline must be positive")
	}

	return &config, nil
}
