package treasury

import (
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/keysign"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"
)

var _ plugin.Spec = (*TreasuryPlugin)(nil)

type TreasuryPlugin struct {
	config       *TreasuryConfig
	vaultStorage *vault.BlockStorageImp
	signer       *keysign.Signer
	db           storage.DatabaseStorage
	eth          *evm.SDK
	logger       logrus.FieldLogger
	verifierApi  *verifierapi.VerifierApi
	jobMutex     sync.Mutex // Prevents race conditions between jobs (load, transact, post etc)
}

func NewTreasuryPlugin(
	config *TreasuryConfig,
	vaultStorage *vault.BlockStorageImp,
	signer *keysign.Signer,
	db storage.DatabaseStorage,
	logger logrus.FieldLogger,
	verifierApi *verifierapi.VerifierApi,
) (*TreasuryPlugin, error) {
	var jobMutex sync.Mutex
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if vaultStorage == nil {
		return nil, fmt.Errorf("vault storage cannot be nil")
	}
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	if verifierApi == nil {
		return nil, fmt.Errorf("verifier api cannot be nil")
	}

	return &TreasuryPlugin{
		config:       config,
		vaultStorage: vaultStorage,
		signer:       signer,
		db:           db,
		logger:       logger,
		verifierApi:  verifierApi,
		jobMutex:     jobMutex,
	}, nil
}

func (tp *TreasuryPlugin) GetRecipeSpecification() (*rtypes.RecipeSchema, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (tp *TreasuryPlugin) ValidatePluginPolicy(policy vtypes.PluginPolicy) error {
	return nil
}

func (tp *TreasuryPlugin) Suggest(configuration map[string]any) (*rtypes.PolicySuggest, error) {
	return nil, fmt.Errorf("unimplemented")
}
