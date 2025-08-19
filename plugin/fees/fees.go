package fees

import (
	"context"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	vcommon "github.com/vultisig/verifier/common"
	"github.com/vultisig/verifier/plugin"
	"github.com/vultisig/verifier/plugin/keysign"
	"github.com/vultisig/verifier/plugin/tx_indexer"
	vtypes "github.com/vultisig/verifier/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/vultisig/verifier/vault"

	"github.com/vultisig/plugin/internal/types"
	"github.com/vultisig/plugin/internal/verifierapi"
	"github.com/vultisig/plugin/storage"
	"github.com/vultisig/recipes/sdk/evm"
	rtypes "github.com/vultisig/recipes/types"
)

/*
All key logic related to fees will go here, that includes
- proposing a fee transaction
- getting fee information
*/

var _ plugin.Spec = (*FeePlugin)(nil)

type FeePlugin struct {
	vaultService     *vault.ManagementService
	vaultStorage     *vault.BlockStorageImp
	signer           *keysign.Signer
	db               storage.DatabaseStorage
	eth              *evm.SDK
	logger           logrus.FieldLogger
	verifierApi      *verifierapi.VerifierApi
	config           *FeeConfig
	txIndexerService *tx_indexer.Service
	asynqInspector   *asynq.Inspector
	asynqClient      *asynq.Client
	encryptionSecret string
	transactingMutex sync.Mutex // when actual transactions are happening we cannot load fees
	ethClient        *ethclient.Client
}

// Suggest implements plugin.Spec.
func (fp *FeePlugin) Suggest(configuration map[string]any) (*rtypes.PolicySuggest, error) {
	panic("unimplemented")
}

func NewFeePlugin(db storage.DatabaseStorage,
	signer *keysign.Signer,
	logger logrus.FieldLogger,
	baseConfigPath string,
	vaultStorage *vault.BlockStorageImp,
	txIndexerService *tx_indexer.Service,
	inspector *asynq.Inspector,
	client *asynq.Client,
	feeConfig *FeeConfig,
	encryptionSecret string,
	verifierUrl string) (*FeePlugin, error) {

	if db == nil {
		return nil, fmt.Errorf("database storage cannot be nil")
	}

	rpcClient, err := ethclient.Dial(feeConfig.EthProvider)
	if err != nil {
		return nil, err
	}

	if _, ok := logger.(*logrus.Logger); !ok {
		return nil, fmt.Errorf("logger must be *logrus.Logger, got %T", logger)
	}

	if vaultStorage == nil {
		return nil, fmt.Errorf("vault storage cannot be nil")
	}

	if verifierUrl == "" {
		return nil, fmt.Errorf("verifier url cannot be empty")
	}

	verifierApi := verifierapi.NewVerifierApi(
		verifierUrl,
		feeConfig.VerifierToken,
		logger.(*logrus.Logger),
	)

	if verifierApi == nil {
		return nil, fmt.Errorf("failed to create verifier api")
	}

	return &FeePlugin{
		db:               db,
		eth:              evm.NewSDK(feeConfig.ChainId, rpcClient, rpcClient.Client()),
		signer:           signer,
		logger:           logger.WithField("plugin", "fees"),
		config:           feeConfig,
		verifierApi:      verifierApi,
		vaultStorage:     vaultStorage,
		txIndexerService: txIndexerService,
		asynqInspector:   inspector,
		asynqClient:      client,
		encryptionSecret: encryptionSecret,
		ethClient:        rpcClient,
	}, nil
}

/* ------------------------------------------------------------------------------------------------
LOADING FEES
here we pull in a list of fees (amounts and ids) that are pending collection and add them to a fee run
------------------------------------------------------------------------------------------------ */

func (fp *FeePlugin) LoadFees(ctx context.Context, task *asynq.Task) error {
	fp.transactingMutex.Lock()
	defer fp.transactingMutex.Unlock()

	fp.logger.Info("Starting Fee Loading Job")

	feePolicies, err := fp.db.GetAllFeePolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy: %w", err)
	}

	// We limit the number of concurrent fee loading operations to 10
	sem := semaphore.NewWeighted(int64(fp.config.Jobs.Load.MaxConcurrentJobs))
	var wg sync.WaitGroup
	var eg errgroup.Group

	for _, feePolicy := range feePolicies {
		wg.Add(1)
		feePolicy = feePolicy
		eg.Go(func() error {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)
			return fp.executeFeeLoading(ctx, feePolicy)
		})
	}

	wg.Wait()
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to execute fee loading: %w", err)
	}
	return nil
}

func (fp *FeePlugin) executeFeeLoading(ctx context.Context, feePolicy vtypes.PluginPolicy) error {

	// Get list of fees from the verifier connected to the fee policy
	feesResponse, err := fp.verifierApi.GetPublicKeysFees(feePolicy.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	// Early return if no fees to collect
	if feesResponse.FeesPendingCollection <= 0 {
		fp.logger.WithField("publicKey", feePolicy.PublicKey).Info("No fees pending collection")
		return nil
	}

	// If fees are greater than 0, we need to collect them
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Fees pending collection: ", feesResponse.FeesPendingCollection)

	checkAmount := 0
	for _, fee := range feesResponse.Fees {
		if !fee.Collected {
			checkAmount += fee.Amount
		}
	}
	if checkAmount != feesResponse.FeesPendingCollection {
		return fmt.Errorf("fees pending collection amount does not match the sum of the fees")
	}

	for _, fee := range feesResponse.Fees {
		if !fee.Collected {

			// Check if the fee has already been loaded and added to a fee run, if so, skip it
			existingFee, err := fp.db.GetFees(ctx, fee.ID)
			if err != nil {
				return fmt.Errorf("failed to get fee: %w", err)
			}
			if len(existingFee) > 0 {
				fp.logger.WithFields(logrus.Fields{
					"publicKey": feePolicy.PublicKey,
					"feeId":     fee.ID,
					"runId":     existingFee[0].FeeRunID,
				}).Info("Fee already added to a fee run")
				continue
			}

			// If the fee hasn't been loaded, look for a draft run and add it to it
			run, err := fp.db.GetPendingFeeRun(ctx, feePolicy.ID)
			if err != nil {
				return fmt.Errorf("failed to get pending fee run: %w", err)
			}

			// If no draft run is found, create a new one and add the fee to it
			if run == nil {
				run, err = fp.db.CreateFeeRun(ctx, feePolicy.ID, types.FeeRunStateDraft, fee)
				if err != nil {
					return fmt.Errorf("failed to create fee run: %w", err)
				}
				fp.logger.WithFields(logrus.Fields{
					"publicKey": feePolicy.PublicKey,
					"feeIds":    []uuid.UUID{fee.ID},
					"runId":     run.ID,
				}).Info("Fee run created")

				// If a draft run is found, add the fee to it
			} else {
				if err := fp.db.CreateFee(ctx, run.ID, fee); err != nil {
					return fmt.Errorf("failed to create fee: %w", err)
				}
				fp.logger.WithFields(logrus.Fields{
					"publicKey": feePolicy.PublicKey,
					"feeIds":    []uuid.UUID{fee.ID},
					"runId":     run.ID,
				}).Info("Fee added to fee run")
			}
		}
	}

	return nil
}

/* ------------------------------------------------------------------------------------------------
HANDLING TRANSACTIONS
here we handle the transactions for a fee run
------------------------------------------------------------------------------------------------ */

func (fp *FeePlugin) HandleTransactions(ctx context.Context, task *asynq.Task) error {
	fp.logger.Info("Starting Fee Transaction Job. Acquiring mutex")
	fp.transactingMutex.Lock()
	fp.logger.Info("Mutex acquired")

	defer func() {
		fp.transactingMutex.Unlock()
		fp.logger.Info("Mutex released")
	}()

	fp.logger.Info("Getting all fee runs")
	runs, err := fp.db.GetAllFeeRuns(ctx)
	if err != nil {
		fp.logger.WithError(err).Error("Failed to get fee runs")
		return fmt.Errorf("failed to get fee runs: %w", err)
	}

	sem := semaphore.NewWeighted(int64(fp.config.Jobs.Transact.MaxConcurrentJobs))
	var wg sync.WaitGroup
	var eg errgroup.Group
	for _, run := range runs {
		run = run
		eg.Go(func() error {
			//TODO also check failed runs
			if run.Status != types.FeeRunStateDraft {
				return nil
			}

			if run.TxHash != nil {
				return nil
			}

			if run.FeeCount == 0 || run.TotalAmount == 0 {
				return nil
			}

			fp.logger.WithFields(logrus.Fields{"runId": run.ID}).Info("Processing fee run")
			feePolicy, err := fp.db.GetPluginPolicy(ctx, run.PolicyID)
			if err != nil {
				return fmt.Errorf("failed to get fee policy: %w", err)
			}
			wg.Add(1)
			fp.logger.WithFields(logrus.Fields{"runId": run.ID, "policyId": run.PolicyID}).Info("Retrieved fee policy")

			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)
			if err := fp.executeFeeTransaction(ctx, run, *feePolicy); err != nil {
				fp.logger.WithFields(logrus.Fields{
					"runId": run.ID,
				}).Error("Failed to execute fee transaction")
				return err
			}
			return nil
		})
	}

	wg.Wait()
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to execute fee transaction: %w", err)
	}

	return nil
}

func (fp *FeePlugin) executeFeeTransaction(ctx context.Context, run types.FeeRun, feePolicy vtypes.PluginPolicy) error {

	fp.logger.WithFields(logrus.Fields{
		"runId":    run.ID,
		"policyId": feePolicy.ID,
	}).Info("Checking if fee run policy id matches fee policy id")
	if run.PolicyID != feePolicy.ID {
		return fmt.Errorf("fee run policy id does not match fee policy id")
	}

	// Get a vault and sign the transactions
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Getting vault")
	vaultFileName := vcommon.GetVaultBackupFilename(feePolicy.PublicKey, vtypes.PluginVultisigFees_feee.String())
	vaultContent, err := fp.vaultStorage.GetVault(vaultFileName)
	if err != nil {
		return fmt.Errorf("failed to get vault: %w", err)
	}
	if vaultContent == nil {
		return fmt.Errorf("vault not found")
	}

	// Propose the transactions
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Proposing transactions")
	keySignRequests, err := fp.proposeTransactions(ctx, feePolicy, run)
	if err != nil {
		return fmt.Errorf("failed to propose transactions: %w", err)
	}
	fp.logger.WithFields(logrus.Fields{
		"publicKey": feePolicy.PublicKey,
	}).Info("Key sign requests proposed")
	for _, keySignRequest := range keySignRequests {
		req := keySignRequest
		if err := fp.initSign(ctx, req, feePolicy, run.ID); err != nil {
			return fmt.Errorf("failed to init sign: %w", err)
		}
	}

	return nil
}
