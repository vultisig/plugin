package fees

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
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
