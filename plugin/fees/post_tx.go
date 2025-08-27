package fees

import (
	"context"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Functions here handle the post-transaction logic. Once a transaction is broadcasted, we need to update the fee run and the fee

func (fp *FeePlugin) HandlePostTx(ctx context.Context, task *asynq.Task) error {
	// Get a list of all fee runs that are in a sent state
	batches, err := fp.db.GetFeeBatchByStatus(ctx, types.FeeBatchStateSent)
	if err != nil {
		fp.logger.WithError(err).Error("failed to get fee runs")
		return fmt.Errorf("failed to get fee runs: %w", err)
	}

	currentBlock, err := fp.ethClient.BlockNumber(ctx)
	if err != nil {
		fp.logger.WithError(err).Error("failed to get current block")
		return fmt.Errorf("failed to get current block: %w", err)
	}

	sem := semaphore.NewWeighted(int64(fp.config.Jobs.Post.MaxConcurrentJobs))
	var wg sync.WaitGroup
	var eg errgroup.Group
	for _, batch := range batches {
		wg.Add(1)
		feeBatch := batch
		eg.Go(func() error {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)
			return fp.updateStatus(ctx, feeBatch, currentBlock)
		})
	}
	wg.Wait()
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to execute fee run status check: %w", err)
	}
	fp.logger.Info("Fee run status check completed")
	return nil
}

func (fp *FeePlugin) updateStatus(ctx context.Context, batch types.FeeBatch, currentBlock uint64) error {
	if batch.TxHash == nil || batch.Status == types.FeeBatchStateDraft {
		return nil
	}
	fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("Beginning status check/update")
	hash := ecommon.HexToHash(*batch.TxHash)

	receipt, err := fp.ethClient.TransactionReceipt(ctx, hash)
	if err == ethereum.NotFound {
		// TODO rebroadcast logic
		fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx not found on chain, rebroadcasting")
		return nil
	}
	if receipt.Status == 1 {
		if currentBlock > receipt.BlockNumber.Uint64()+fp.config.Jobs.Post.SuccessConfirmations {
			fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx successful, setting to success")

			// This is semi critical code as it could create a state mismatch between the verifier and the database.
			if err = fp.db.SetFeeBatchStatus(ctx, nil, batch.BatchID, types.FeeBatchStateSuccess); err != nil {
				return fmt.Errorf("failed to set fee batch success: %w", err)
			}
		} else {
			fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx successful, but not enough confirmations, waiting for more")
			return nil
		}
	} else {
		// TODO failed tx logic
		fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx failed, setting to failed")
		fp.verifierApi.RevertFeeCredit(*batch.TxHash, batch.BatchID)
		return nil
	}
	return nil
}
