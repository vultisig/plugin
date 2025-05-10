// plugin/dca/config.go
package dca

import (
	"errors"
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

func loadPluginConfig() (*PluginConfig, error) {
	configPath := filepath.Join("plugin", "dca", "dca.yml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

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
