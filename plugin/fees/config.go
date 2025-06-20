package fees

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

/*
	{
	  "type": "fees",
	  "version": "1.0.0",
	  "rpc_url": "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY",
	  "usdc_address": "0xA0b86a33E6441b8C4C8C8C8C8C8C8C8C8C8C8C8C",
	  "gas": {
	    "limit_multiplier": 1,
	    "price_multiplier": 1
	  },
	  "monitoring": {
	    "timeout_minutes": 30,
	    "check_interval_seconds": 60
	  }
	}
*/

type FeeConfig struct {
	Type             string `mapstructure:"type"`
	Version          string `mapstructure:"version"`
	RpcURL           string `mapstructure:"rpc_url"`           // URL for the RPC endpoint to interact with the ethereum/evm blockchain
	USDCAddress      string `mapstructure:"usdc_address"`      // If a non-ethereum chain is used, this is the address of the USDC token contract on that chain
	VerifierUrl      string `mapstructure:"verifier_url"`      // The url of the verifier (i.e. the counter party to sign transactions).
	CollectorAddress string `mapstructure:"collector_address"` // The address of the collector of the fees.
	Gas              struct {
		LimitMultiplier int `mapstructure:"limit_multiplier"`
		PriceMultiplier int `mapstructure:"price_multiplier"`
	} `mapstructure:"gas"`
	Monitoring struct {
		TimeoutMinutes       int `mapstructure:"timeout_minutes"`
		CheckIntervalSeconds int `mapstructure:"check_interval_seconds"`
	} `mapstructure:"monitoring"`
}

type ConfigOption func(*FeeConfig) error

func withDefaults(c *FeeConfig) {
	c.Type = PLUGIN_TYPE
	c.Version = "1.0.0"
	c.RpcURL = "https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY"
	c.USDCAddress = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	c.VerifierUrl = ""
	c.Gas.LimitMultiplier = 1
	c.Gas.PriceMultiplier = 1
	c.Monitoring.TimeoutMinutes = 30
	c.Monitoring.CheckIntervalSeconds = 60
}

func WithEthConfig(rpcUrl string, usdcAddress string) ConfigOption {
	return func(c *FeeConfig) error {
		c.RpcURL = rpcUrl
		c.USDCAddress = usdcAddress
		return nil
	}
}

func WithVerifierUrl(verifierUrl string) ConfigOption {
	return func(c *FeeConfig) error {
		c.VerifierUrl = verifierUrl
		return nil
	}
}

func WithCollectorAddress(collectorAddress string) ConfigOption {
	// TODO garry. Verify address whitelisted. Verify address is valid.
	return func(c *FeeConfig) error {
		c.CollectorAddress = collectorAddress
		return nil
	}
}

func NewFeeConfig(fns ...ConfigOption) (*FeeConfig, error) {
	c := &FeeConfig{}
	withDefaults(c)
	for _, fn := range fns {
		if err := fn(c); err != nil {
			return nil, err
		}
	}

	// Validate configuration
	if c.Type != PLUGIN_TYPE {
		return c, fmt.Errorf("invalid plugin type: %s", c.Type)
	}
	if c.RpcURL == "" {
		return c, errors.New("rpc_url is required")
	}
	if c.Gas.LimitMultiplier <= 0 {
		return c, errors.New("gas limit multiplier must be positive")
	}
	if c.VerifierUrl == "" {
		return c, errors.New("verifier_url is required")
	}

	return c, nil
}

func WithFileConfig(basePath string) ConfigOption {
	return func(c *FeeConfig) error {

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
			return fmt.Errorf("failed to read config: %w", err)
		}

		if err := v.Unmarshal(c); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		return nil
	}
}

/* Fee collection types
Can be collected:
   - by public key (all active plugins)
   - by policy
   - by plugin id
*/

type FeeCollectionType int

const (
	FeeCollectionTypeByPublicKey FeeCollectionType = iota
	FeeCollectionTypeByPolicy
	FeeCollectionTypeByPluginID
	FeeCollectionTypeAll
)

type FeeCollectionFormat struct {
	FeeCollectionType FeeCollectionType `json:"fee_collection_type"`
	Value             string            `json:"value"` // will use this as the key value, should be empty string for FeeCollectionTypeAll
}
