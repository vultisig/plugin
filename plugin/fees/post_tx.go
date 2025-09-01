package fees

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/types"
	vtypes "github.com/vultisig/verifier/types"
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
	eg, ctx := errgroup.WithContext(ctx)
	for _, batch := range batches {
		feeBatch := batch
		eg.Go(func() error {
			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)
			if err := fp.updateStatus(ctx, feeBatch, currentBlock); err != nil {
				fp.logger.WithField("batch_id", feeBatch.BatchID).Error("Failed to update fee batch status", err)
			} else {
				fp.logger.WithField("batch_id", feeBatch.BatchID).Info("Fee batch status update run successfully")
			}
			return nil
		})
	}
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

	// Tx successful
	if receipt.Status == 1 {
		if currentBlock > receipt.BlockNumber.Uint64()+fp.config.Jobs.Post.SuccessConfirmations {
			fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx successful, setting to success")

			tx, err := fp.db.Pool().Begin(ctx)
			if err != nil {
				return err
			}

			var rollbackErr error
			defer func() {
				if rollbackErr != nil {
					tx.Rollback(ctx)
				}
			}()

			hash := ""
			if batch.TxHash != nil {
				hash = *batch.TxHash
			}

			resp, err := fp.verifierApi.UpdateFeeBatch(batch.PublicKey, batch.BatchID, hash, types.FeeBatchStateSuccess)
			if err != nil {
				rollbackErr = err
				return fmt.Errorf("failed to update verifier fee batch to success: %w", err)
			}
			if resp.Error.Message != "" {
				rollbackErr = fmt.Errorf("failed to update verifier fee batch to success: %s", resp.Error.Message)
				return fmt.Errorf("failed to update verifier fee batch to success: %s", resp.Error.Message)
			}

			if err = fp.db.SetFeeBatchStatus(ctx, tx, batch.BatchID, types.FeeBatchStateSuccess); err != nil {
				rollbackErr = err
				return fmt.Errorf("failed to update verifier fee batch to success: %w", err)
			}

			if err = tx.Commit(ctx); err != nil {
				rollbackErr = err
				return fmt.Errorf("failed to commit transaction: %w", err)
			}
		} else {
			fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx successful, but not enough confirmations, waiting for more")
			return nil
		}
	} else {
		// Handle failed tx - in this case, we simply set the batch to failed. And request for the verifier to create a new debit line of "failed tx"
		return fp.handleFailedTx(ctx, batch)
	}
	return nil
}

// This function sets a batch id to be failed and requests for a new debit line to be created. The failed tx then gets picked up in a new batch.
func (fp *FeePlugin) handleFailedTx(ctx context.Context, batch types.FeeBatch) error {
	fp.logger.WithFields(logrus.Fields{"batch_id": batch.BatchID}).Info("tx failed, setting to failed")

	tx, err := fp.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	var rollbackErr error
	defer func() {
		if rollbackErr != nil {
			tx.Rollback(ctx)
		}
	}()

	// This api call automatically creates a new debit line for the failed tx, which will get picked up in a new batch.
	err = fp.db.SetFeeBatchStatus(ctx, tx, batch.BatchID, types.FeeBatchStateFailed)
	if err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to set fee batch status to failed: %w", err)
	}

	hash := ""
	if batch.TxHash != nil {
		hash = *batch.TxHash
	}
	resp, err := fp.verifierApi.UpdateFeeBatch(batch.PublicKey, batch.BatchID, hash, types.FeeBatchStateFailed)
	if err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to update verifier fee batch to failed: %w", err)
	}
	if resp.Error.Message != "" {
		rollbackErr = fmt.Errorf("failed to update verifier fee batch to failed: %s", resp.Error.Message)
		return fmt.Errorf("failed to update verifier fee batch to failed: %s", resp.Error.Message)
	}

	if err = tx.Commit(ctx); err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	feePolicies, err := fp.db.GetPluginPolicies(ctx, batch.PublicKey, vtypes.PluginVultisigFees_feee, true)
	if err != nil {
		rollbackErr = err
		return fmt.Errorf("failed to get plugin policy: %w", err)
	}

	if len(feePolicies) < 1 {
		rollbackErr = err
		return fmt.Errorf("failed to get plugin policy: %w", err)
	}

	feePolicy := feePolicies[0]

	// Immediately load a new fee batch
	return fp.executeFeeLoading(ctx, feePolicy)
}
