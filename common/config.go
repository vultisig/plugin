package common

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/verifier/vault_config"
)

var coreconfig *CoreConfig

type ServerConfig struct {
	Host             string `mapstructure:"host" json:"host,omitempty"`
	Port             int64  `mapstructure:"port" json:"port,omitempty"`
	EncryptionSecret string `mapstructure:"encryption_secret" json:"encryption_secret,omitempty"`
	VerifierUrl      string `mapstructure:"verifier_url" json:"verifier_url,omitempty"`         //The url of the verifier (i.e. the counter party to sign transactions).
	VaultsFilePath   string `mapstructure:"vaults_file_path" json:"vaults_file_path,omitempty"` //This is just for testing locally
}

type CoreConfig struct {
	Server   ServerConfig `mapstructure:"server" json:"server"`
	Database struct {
		DSN string `mapstructure:"dsn" json:"dsn,omitempty"`
	} `mapstructure:"database" json:"database,omitempty"`
	BaseConfigPath     string                    `mapstructure:"base_config_path" json:"base_config_path,omitempty"`
	Redis              storage.RedisConfig       `mapstructure:"redis" json:"redis,omitempty"`
	BlockStorage       vault_config.BlockStorage `mapstructure:"block_storage" json:"block_storage,omitempty"`
	VaultServiceConfig vault_config.Config       `mapstructure:"vault_service" json:"vault_service,omitempty"`
	Datadog            struct {
		Host string `mapstructure:"host" json:"host,omitempty"`
		Port string `mapstructure:"port" json:"port,omitempty"`
	} `mapstructure:"datadog" json:"datadog"`
}

func LoadConfig() error {
	configName := os.Getenv("VS_CONFIG_NAME")
	if configName == "" {
		configName = "config"
	}

	c, err := ReadConfig(configName)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	coreconfig = c
	return nil
}

func ReadConfig(configName string) (*CoreConfig, error) {
	viper.SetConfigName(configName)
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	viper.SetDefault("Server.VaultsFilePath", "vaults")

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("fail to reading config file, %w", err)
	}
	var cfg CoreConfig
	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to decode into struct, %w", err)
	}
	return &cfg, nil
}

// New singleton for handling system config values across plugins.
func GetConfig() *CoreConfig {
	return coreconfig
}
