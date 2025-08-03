package fees

import (
	"context"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum"
	ecommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	etypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/plugin/internal/types"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Functions here handle the post-transaction logic. Once a transaction is broadcasted, we need to update the fee run and the fee

func (fp *FeePlugin) HandlePostTx(ctx context.Context, task *asynq.Task) error {
	// Get a list of all fee runs that are in a sent state
	runs, err := fp.db.GetAllFeeRuns(ctx, types.FeeRunStateSent)
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
	for _, run := range runs {
		wg.Add(1)
		run = run
		eg.Go(func() error {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return fmt.Errorf("failed to acquire semaphore: %w", err)
			}
			defer sem.Release(1)
			if run.TxHash == nil || run.Status == types.FeeRunStateDraft {
				return nil
			}
			return fp.updateStatus(ctx, run, currentBlock)
		})
	}
	wg.Wait()
	if err := eg.Wait(); err != nil {
		fp.logger.WithError(err).Error("failed to execute fee run status check")
		return fmt.Errorf("failed to execute fee run status check: %w", err)
	}
	fp.logger.Info("Fee run status check completed")
	return nil
}

func (fp *FeePlugin) updateStatus(ctx context.Context, run types.FeeRun, currentBlock uint64) error {
	if run.TxHash == nil || run.Status == types.FeeRunStateDraft {
		return nil
	}
	fp.logger.WithFields(logrus.Fields{"run_id": run.ID}).Info("Beginning status check/update")
	hash := ecommon.HexToHash(*run.TxHash)

	receipt, err := fp.ethClient.TransactionReceipt(ctx, hash)
	if err == ethereum.NotFound {
		lastTxs, err := fp.db.GetFeeRunTxs(ctx, run.ID)
		if err != nil {
			return fmt.Errorf("failed to get fee run txs: %w", err)
		}
		if len(lastTxs) == 0 {
			return fmt.Errorf("no tx found for run %s", run.ID)
		}
		txHex := lastTxs[0].Tx

		var tx etypes.Transaction
		txBytes, err := hexutil.Decode(txHex)
		if err != nil {
			return fmt.Errorf("failed to decode tx: %w", err)
		}
		if err := tx.UnmarshalBinary(txBytes); err != nil {
			return fmt.Errorf("failed to unmarshal tx: %w", err)
		}

		fromAddress, err := fp.getEthAddressFromFeePolicyId(run.PolicyID)
		if err != nil {
			return fmt.Errorf("failed to get eth address from fee policy: %w", err)
		}

		nonce, err := fp.ethClient.PendingNonceAt(ctx, ecommon.HexToAddress(fromAddress))
		if err != nil {
			return fmt.Errorf("failed to get pending nonce: %w", err)
		}

		// Rebroadcast if pending nonce is the same as the nonce in the tx
		if tx.Nonce() == nonce {
			var err error
			dbTx, err := fp.db.Pool().Begin(ctx)
			if err != nil {
				return fmt.Errorf("failed to begin transaction: %w", err)
			}
			txBytes, err := tx.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed to marshal tx: %w", err)
			}
			defer func() {
				if err != nil {
					if err := dbTx.Rollback(ctx); err != nil {
						fp.logger.WithError(err).Error("failed to rollback transaction")
					}
				} else {
					if err := dbTx.Commit(ctx); err != nil {
						fp.logger.WithError(err).Error("failed to commit transaction")
					}
				}
			}()
			err = fp.db.CreateFeeRunTx(ctx, dbTx, run.ID, txBytes, tx.Hash().Hex(), 0, fp.config.ChainId)
			if err != nil {
				return fmt.Errorf("failed to create fee run tx: %w", err)
			}
			err = fp.ethClient.SendTransaction(ctx, &tx)
			if err != nil {
				return fmt.Errorf("failed to send tx: %w", err)
			}

			fp.logger.WithFields(logrus.Fields{"run_id": run.ID}).Info("tx rebroadcasted")
			return nil
		} else {
			//TODO handle an earlier nonce or later nonce
			return nil
		}
	}
	if receipt.Status == 1 {
		if currentBlock > receipt.BlockNumber.Uint64()+fp.config.Jobs.Post.SuccessConfirmations {
			fp.logger.WithFields(logrus.Fields{"run_id": run.ID}).Info("tx successful, setting to success")

			ids := []uuid.UUID{}
			for _, fee := range run.Fees {
				ids = append(ids, fee.ID)
			}

			dbTx, err := fp.db.Pool().Begin(ctx)
			if err != nil {
				return fmt.Errorf("failed to begin transaction: %w", err)
			}
			var txErr error
			defer func() {
				if txErr != nil {
					dbTx.Rollback(ctx)
				} else {
					dbTx.Commit(ctx)
				}
			}()

			if txErr = fp.db.SetFeeRunSuccess(ctx, dbTx, run.ID); err != nil {
				return fmt.Errorf("failed to set fee run success: %w", err)
			}

			// include this in the errors too, as if the verifier is not updated, the there will be a state mismatch between the verifier and the plugin.
			if txErr = fp.verifierApi.MarkFeeAsCollected(*run.TxHash, run.CreatedAt, ids...); err != nil {
				return fmt.Errorf("failed to mark fee as collected on verifier: %w", err)
			}

		} else {
			fp.logger.WithFields(logrus.Fields{"run_id": run.ID}).Info("tx successful, but not enough confirmations, waiting for more")
			return nil
		}
	} else {
		// TODO failed tx logic
		fp.logger.WithFields(logrus.Fields{"run_id": run.ID}).Info("tx failed, setting to failed")
		return nil
	}
	return nil
}
