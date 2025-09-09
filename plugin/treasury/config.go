package treasury

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/spf13/viper"
	"github.com/vultisig/recipes/sdk/evm"
)

type TreasuryConfig struct {
	EthProvider      *ethclient.Client
	ChainId          *big.Int
	SDK              *evm.SDK
	EncryptionSecret string
	Jobs             struct {
		Load struct {
			Cronexpr string `mapstructure:"cronexpr"`
		} `mapstructure:"load"`
		Transact struct {
			Cronexpr string `mapstructure:"cronexpr"`
		} `mapstructure:"transact"`
		Post struct {
			Cronexpr string `mapstructure:"cronexpr"`
		} `mapstructure:"post"`
	}
}

type TreasuryConfigWrapper struct {
	TreasuryConfig `mapstructure:",squash"`
	ChainIdRaw     uint64 `mapstructure:"chain_id"`
	EthProviderRaw string `mapstructure:"eth_provider"`
}

type ConfigOption func(*TreasuryConfigWrapper) error

func withDefaults(c *TreasuryConfigWrapper) {
	c.ChainIdRaw = 1
	c.EthProviderRaw = "https://eth.public-rpc.com"
	c.Jobs.Load.Cronexpr = "@every 10s"
	c.Jobs.Transact.Cronexpr = "@every 10s"
	c.Jobs.Post.Cronexpr = "@every 10s"
}

func WithChainIdRaw(chainIdRaw uint64) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.ChainIdRaw = chainIdRaw
		return nil
	}
}

func WithEthProviderRaw(ethProviderRaw string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.EthProviderRaw = ethProviderRaw
		return nil
	}
}

func WithEncryptionSecret(encryptionSecret string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.EncryptionSecret = encryptionSecret
		return nil
	}
}

func WithCronexpr(load, transact, post string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		WithLoadTiming(load)(c)
		WithTransactTiming(transact)(c)
		WithPostTiming(post)(c)
		return nil
	}
}

func WithLoadTiming(load string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.Jobs.Load.Cronexpr = load
		return nil
	}
}

func WithTransactTiming(transact string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.Jobs.Transact.Cronexpr = transact
		return nil
	}
}

func WithPostTiming(post string) ConfigOption {
	return func(c *TreasuryConfigWrapper) error {
		c.Jobs.Post.Cronexpr = post
		return nil
	}
}
func WithFileConfig(basePath string) ConfigOption {

	return func(c *TreasuryConfigWrapper) error {
		v := viper.New()
		v.SetConfigName("treasury")

		// Add config paths in order of precedence
		if basePath != "" {
			v.AddConfigPath(basePath)
		}
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/vultisig")

		// Enable environment variable overrides
		v.AutomaticEnv()
		v.SetEnvPrefix("TREASURY")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}

		var wrappedConfig TreasuryConfigWrapper
		if err := v.Unmarshal(&wrappedConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		*c = wrappedConfig
		return nil
	}
}

func postConfigLoad(c *TreasuryConfigWrapper) error {
	if c.ChainId == nil {
		c.ChainId = big.NewInt(0).SetUint64(c.ChainIdRaw)
	}
	if c.EthProvider == nil {
		var err error
		c.EthProvider, err = ethclient.Dial(c.EthProviderRaw)
		if err != nil {
			return fmt.Errorf("failed to dial eth provider: %w", err)
		}
	}
	if c.SDK == nil {
		c.SDK = evm.NewSDK(c.ChainId, c.EthProvider, c.EthProvider.Client())
	}
	return nil
}

func NewTreasuryConfig(fns ...ConfigOption) (*TreasuryConfig, error) {
	c := &TreasuryConfigWrapper{}
	withDefaults(c)
	for _, fn := range fns {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if err := postConfigLoad(c); err != nil {
		return nil, err
	}
	return &c.TreasuryConfig, nil
}
