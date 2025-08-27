package fees

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/vultisig/plugin/internal/types"
	vtypes "github.com/vultisig/verifier/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

/* This code section is concerned with pulling fees into the plugin server */

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
			err := fp.executeFeeLoading(ctx, feePolicy)
			if err != nil {
				fp.logger.WithError(err).WithField("public_key", feePolicy.PublicKey).Error("Failed to execute fee loading")
			}
			return err
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
	batch, err := fp.verifierApi.CreateFeeBatch(feePolicy.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to get plugin policy fees: %w", err)
	}

	if err != nil {
		return fmt.Errorf("failed to create fee batch: %w", err)
	}

	if batch.Amount == 0 || batch.BatchID == uuid.Nil {
		fp.logger.WithField("public_key", feePolicy.PublicKey).Info("No fees to load")
		return nil
	}

	_, err = fp.db.CreateFeeBatch(ctx, nil, types.FeeBatch{
		ID:        uuid.New(),
		BatchID:   batch.BatchID,
		PublicKey: feePolicy.PublicKey,
		Status:    types.FeeBatchStateDraft,
		TxHash:    nil,
		Amount:    uint64(batch.Amount),
	})

	return err
}
