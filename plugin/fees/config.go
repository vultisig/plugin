package fees

import (
	"errors"
	"fmt"
	"math/big"
	"slices"
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

// These are properties and parameters specific to the fee plugin config. They should be distinct from system/core config
type FeeConfig struct {
	Type                        string   `mapstructure:"type"`
	Version                     string   `mapstructure:"version"`
	RpcURL                      string   `mapstructure:"rpc_url"`                       // URL for the RPC endpoint to interact with the ethereum/evm blockchain
	CollectorWhitelistAddresses []string `mapstructure:"collector_whitelist_addresses"` // A list of whitelisted addresses for which fee transactions are collected against. These can include previous addresses. Fee plugins with a recipient address that is not in this list will not be processed.
	CollectorAddress            string   `mapstructure:"collector_address"`             // This address is what is used for new policies. Fee policies created with a different address will be rejected.
	MaxFeeAmount                uint64   `mapstructure:"max_fee_amount"`                // Policies that are created/submitted which do not have this amount will be rejected.
	UsdcAddress                 string   `mapstructure:"usdc_address"`                  // The address of the USDC token on the Ethereum blockchain.
	VerifierToken               string   `mapstructure:"verifier_token"`                // The token to use for the verifier API.
	ChainId                     *big.Int `mapstructure:"chain_id"`                      // The chain ID of the Ethereum blockchain.
}

type ConfigOption func(*FeeConfig) error

func withDefaults(c *FeeConfig) {
	c.ChainId = big.NewInt(1)
	c.Type = PLUGIN_TYPE
	c.Version = "1.0.0"
	c.RpcURL = "https://ethereum.publicnode.com/"
	c.CollectorWhitelistAddresses = []string{}
	c.CollectorAddress = ""
	c.MaxFeeAmount = 500e6 // 500 USDC
}

func WithEthConfig(rpcUrl string) ConfigOption {
	return func(c *FeeConfig) error {
		c.RpcURL = rpcUrl
		return nil
	}
}

func WithCollectorAddress(collectorAddress string) ConfigOption {
	return func(c *FeeConfig) error {
		c.CollectorAddress = collectorAddress
		return nil
	}
}

func WithCollectorWhitelistAddresses(collectorWhitelistAddresses []string) ConfigOption {
	return func(c *FeeConfig) error {
		c.CollectorWhitelistAddresses = collectorWhitelistAddresses
		return nil
	}
}

func WithMaxFeeAmount(maxFeeAmount uint64) ConfigOption {
	return func(c *FeeConfig) error {
		c.MaxFeeAmount = maxFeeAmount
		return nil
	}
}

func WithChainId(chainId *big.Int) ConfigOption {
	return func(c *FeeConfig) error {
		c.ChainId = chainId
		return nil
	}
}

func WithFileConfig(basePath string) ConfigOption {
	return func(c *FeeConfig) error {

		v := viper.New()
		v.SetConfigName("fee")

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
	// Collector address cannot be empty
	if c.CollectorAddress == "" {
		return c, errors.New("collector_address is required")
	}

	// There must be at least one collector whitelist address
	if len(c.CollectorWhitelistAddresses) == 0 {
		return c, errors.New("collector_whitelist_addresses is required")
	}

	// Collector address must be in the whitelist
	if !slices.Contains(c.CollectorWhitelistAddresses, c.CollectorAddress) {
		return c, fmt.Errorf("collector_address must be in the whitelist: %s, whitelist: %v", c.CollectorAddress, c.CollectorWhitelistAddresses)
	}

	if c.VerifierToken == "" {
		return c, errors.New("verifier_token is required")
	}

	if c.ChainId == nil {
		return c, errors.New("chain_id is required")
	}

	return c, nil
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
