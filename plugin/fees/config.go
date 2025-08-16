package fees

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/spf13/viper"
)

// These are properties and parameters specific to the fee plugin config. They should be distinct from system/core config
type FeeConfig struct {
	Type          string   `mapstructure:"type"`
	Version       string   `mapstructure:"version"`
	MaxFeeAmount  uint64   `mapstructure:"max_fee_amount"` // Policies that are created/submitted which do not have this amount will be rejected.
	UsdcAddress   string   `mapstructure:"usdc_address"`   // The address of the USDC token on the Ethereum blockchain.
	VerifierToken string   `mapstructure:"verifier_token"` // The token to use for the verifier API.
	ChainId       *big.Int // The chain ID as a big.Int (initialized from ChainIdRaw).
	EthProvider   string   `mapstructure:"eth_provider"` // The Ethereum provider to use for the fee plugin.
	Jobs          struct {
		Load struct {
			MaxConcurrentJobs uint64 `mapstructure:"max_concurrent_jobs"` //How many consecutive tasks can take place
			Cronexpr          string `mapstructure:"cronexpr"`            // Cron link expression on how often these tasks should run
		} `mapstructure:"load"`
		Transact struct {
			MaxConcurrentJobs uint64 `mapstructure:"max_concurrent_jobs"` //How many consecutive tasks can take place
			Cronexpr          string `mapstructure:"cronexpr"`            // Cron link expression on how often these tasks should run
		} `mapstructure:"transact"`
		Post struct {
			SuccessConfirmations uint64 `mapstructure:"success_confirmations"` //How many consecutive tasks can take place
			Cronexpr             string `mapstructure:"cronexpr"`              // Cron link expression on how often these tasks should run
			MaxConcurrentJobs    uint64 `mapstructure:"max_concurrent_jobs"`
		} `mapstructure:"post"`
	}
	DryRun bool `mapstructure:"dry_run"`
}

type FeeConfigFileWrapper struct {
	FeeConfig  `mapstructure:",squash"`
	ChainIdRaw uint64 `mapstructure:"chain_id"`
}

type ConfigOption func(*FeeConfig) error

func withDefaults(c *FeeConfig) {
	c.ChainId = big.NewInt(1)
	c.Type = PLUGIN_TYPE
	c.Version = "1.0.0"
	c.MaxFeeAmount = 500e6 // 500 USDC

	c.Jobs.Load.MaxConcurrentJobs = 10
	c.Jobs.Transact.MaxConcurrentJobs = 10
	c.Jobs.Post.MaxConcurrentJobs = 10
	c.Jobs.Post.SuccessConfirmations = 20

	c.Jobs.Load.Cronexpr = "@every 2m"
	c.Jobs.Transact.Cronexpr = "0 12 * * 5"
	c.Jobs.Post.Cronexpr = "@every 5m"
	c.DryRun = false
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

func WithEthClient(url string) ConfigOption {
	return func(c *FeeConfig) error {
		c.EthProvider = url
		return nil
	}
}

func WithSuccessConfirmations(successConfirmations uint64) ConfigOption {
	return func(c *FeeConfig) error {
		c.Jobs.Post.SuccessConfirmations = successConfirmations
		return nil
	}
}

func WithJobConcurrency(load, transact, post uint64) ConfigOption {
	return func(c *FeeConfig) error {
		c.Jobs.Load.MaxConcurrentJobs = load
		c.Jobs.Transact.MaxConcurrentJobs = transact
		c.Jobs.Post.MaxConcurrentJobs = post
		return nil
	}
}

func WithCronexpr(load, transact, post string) ConfigOption {
	return func(c *FeeConfig) error {
		c.Jobs.Load.Cronexpr = load
		c.Jobs.Transact.Cronexpr = transact
		c.Jobs.Post.Cronexpr = post
		return nil
	}
}

func WithDryRun(dryRun bool) ConfigOption {
	return func(c *FeeConfig) error {
		c.DryRun = dryRun
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

		var wrappedConfig FeeConfigFileWrapper
		if err := v.Unmarshal(&wrappedConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}

		// Copy all values from the wrapped config to the original config
		*c = wrappedConfig.FeeConfig

		c.ChainId = big.NewInt(0).SetUint64(wrappedConfig.ChainIdRaw)
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

	if c.VerifierToken == "" {
		return c, errors.New("verifier_token is required")
	}

	if c.ChainId == nil || c.ChainId.Uint64() == 0 {
		return c, errors.New("chain_id is required and must not be 0")
	}

	if c.EthProvider == "" {
		return c, errors.New("eth_provider is required")
	}

	if c.Jobs.Load.MaxConcurrentJobs < 1 ||
		c.Jobs.Load.MaxConcurrentJobs > 100 ||
		c.Jobs.Transact.MaxConcurrentJobs < 1 ||
		c.Jobs.Transact.MaxConcurrentJobs > 100 ||
		c.Jobs.Post.MaxConcurrentJobs < 1 ||
		c.Jobs.Post.MaxConcurrentJobs > 100 {
		return c, errors.New("max_concurrent_jobs must be greater than 0 and less than 100")
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
