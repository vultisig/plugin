package copytrader

import (
	"context"
	"fmt"

	gcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/mobile-tss-lib/tss"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
	"github.com/vultisig/verifier/common"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/internal/keysign"
	"github.com/vultisig/plugin/storage"
)

const UniswapV2RouterAddress = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"

var UniswapSwapTopic = gcommon.HexToHash("0xd78ad95fa46c994b6551d0da85fc275fe613ce37657fb8d5e3d130840159d822")

var _ plugin.Plugin = (*Plugin)(nil)

type Plugin struct {
	db                    storage.DatabaseStorage
	signer                *keysign.Signer
	eth                   *evm.SDK
	ethRpc                *ethclient.Client
	logger                logrus.FieldLogger
	txIndexerService      *tx_indexer.Service
	client                *asynq.Client
	vaultStorage          vault.Storage
	vaultEncryptionSecret string
	blockID               uint64
}

func NewPlugin(
	db storage.DatabaseStorage,
	signer *keysign.Signer,
	vaultStorage vault.Storage,
	ethRpc *ethclient.Client,
	txIndexerService *tx_indexer.Service,
	client *asynq.Client,
	vaultEncryptionSecret string,
) (*Plugin, error) {
	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	var (
		eth          *evm.SDK
		currentBlock uint64
	)
	if ethRpc != nil {
		ethEvmChainID, err := common.Ethereum.EvmID()
		if err != nil {
			return nil, fmt.Errorf("failed to get Ethereum EVM ID: %w", err)
		}
		eth = evm.NewSDK(ethEvmChainID, ethRpc, ethRpc.Client())

		currentBlock, err = ethRpc.BlockNumber(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to get block: %w", err)
		}
	}

	return &Plugin{
		db:                    db,
		signer:                signer,
		eth:                   eth,
		ethRpc:                ethRpc,
		logger:                logrus.WithField("plugin", "copytrader"),
		txIndexerService:      txIndexerService,
		client:                client,
		vaultStorage:          vaultStorage,
		vaultEncryptionSecret: vaultEncryptionSecret,
		blockID:               currentBlock,
	}, nil
}

func (p *Plugin) GetRecipeSpecification() *rtypes.RecipeSchema {
	return &rtypes.RecipeSchema{
		Version:         1, // Schema version
		ScheduleVersion: 1, // Schedule specification version
		// TODO: configure
		PluginId:      string(vtypes.PluginVultisigCopytrader_0000),
		PluginName:    "Copy trading plugin",
		PluginVersion: 1, // Convert from "0.1.0" to int32
		SupportedResources: []*rtypes.ResourcePattern{
			{
				ResourcePath: &rtypes.ResourcePath{
					ChainId:    "ethereum",
					ProtocolId: "uniswapv2_router",
					FunctionId: "swapExactTokensForTokens",
					Full:       "ethereum.uniswapv2_router.swapExactTokensForTokens",
				},
				ParameterCapabilities: []*rtypes.ParameterConstraintCapability{
					{
						ParameterName: "aim",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "source_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "destination_token",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_WHITELIST,
						},
						Required: true,
					},
					{
						ParameterName: "amount",
						SupportedTypes: []rtypes.ConstraintType{
							rtypes.ConstraintType_CONSTRAINT_TYPE_FIXED,
							rtypes.ConstraintType_CONSTRAINT_TYPE_MAX,
							rtypes.ConstraintType_CONSTRAINT_TYPE_RANGE,
						},
						Required: true,
					},
				},
				Required: true,
			},
		},
		Requirements: &rtypes.PluginRequirements{
			MinVultisigVersion: 1,
			SupportedChains:    []string{"ethereum"},
		},
	}
}

func (p *Plugin) ProposeTransactions(policy vtypes.PluginPolicy) ([]vtypes.PluginKeysignRequest, error) {
	//TODO implement me
	panic("implement me")
}

func (p *Plugin) initSign(
	ctx context.Context,
	req vtypes.PluginKeysignRequest,
	pluginPolicy vtypes.PluginPolicy,
) error {
	sigs, err := p.signer.Sign(ctx, req)
	if err != nil {
		p.logger.WithError(err).Error("Keysign failed")
		return fmt.Errorf("failed to sign transaction: %w", err)
	}

	if len(sigs) != 1 {
		p.logger.
			WithField("sigs_count", len(sigs)).
			Error("expected only 1 message+sig per request for evm")
		return fmt.Errorf("failed to sign transaction: invalid signature count: %d", len(sigs))
	}
	var sig tss.KeysignResponse
	for _, s := range sigs {
		sig = s
	}

	err = p.SigningComplete(ctx, sig, req, pluginPolicy)
	if err != nil {
		p.logger.WithError(err).Error("failed to complete signing process (broadcast tx)")
		return fmt.Errorf("failed to complete signing process: %w", err)
	}
	return nil
}

func (p *Plugin) SigningComplete(
	ctx context.Context,
	signature tss.KeysignResponse,
	signRequest vtypes.PluginKeysignRequest,
	_ vtypes.PluginPolicy,
) error {
	tx, err := p.eth.Send(
		ctx,
		gcommon.FromHex(signRequest.Transaction),
		gcommon.Hex2Bytes(signature.R),
		gcommon.Hex2Bytes(signature.S),
		gcommon.Hex2Bytes(signature.RecoveryID),
	)
	if err != nil {
		p.logger.WithError(err).WithField("tx_hex", signRequest.Transaction).Error("p.eth.Send")
		return fmt.Errorf("p.eth.Send(tx_hex=%s): %w", signRequest.Transaction, err)
	}

	p.logger.WithFields(logrus.Fields{
		"from_public_key": signRequest.PublicKey,
		"to_address":      tx.To().Hex(),
		"hash":            tx.Hash().Hex(),
		"chain":           vcommon.Ethereum.String(),
	}).Info("tx successfully signed and broadcasted")
	return nil
}
