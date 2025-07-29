package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/tx_indexer/pkg/graceful"
	"golang.org/x/sync/errgroup"
)

type Worker struct {
	logger *logrus.Logger

	client *asynq.Client
	task   string
	queue  string

	repo     Storage
	interval Interval
	policy   PolicyFetcher

	pollInterval     time.Duration
	iterationTimeout time.Duration
}

func NewWorker(
	logger *logrus.Logger,
	client *asynq.Client,
	task,
	queue string,
	repo Storage,
	interval Interval,
	policy PolicyFetcher,
) *Worker {
	return &Worker{
		logger:           logger.WithField("pkg", "scheduler.Worker").Logger,
		client:           client,
		task:             task,
		queue:            queue,
		repo:             repo,
		interval:         interval,
		policy:           policy,
		pollInterval:     30 * time.Second,
		iterationTimeout: 30 * time.Second,
	}
}

func (w *Worker) Run() error {
	ctx, stop := context.WithCancel(context.Background())

	go func() {
		graceful.HandleSignals(stop)
		w.logger.Info("got exit signal, will stop after current processing step finished...")
	}()

	err := w.start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}
	return nil
}

func (w *Worker) start(aliveCtx context.Context) error {
	err := w.enqueue()
	if err != nil {
		return fmt.Errorf("failed to enqueue: %w", err)
	}

	for {
		select {
		case <-aliveCtx.Done():
			w.logger.Infof("context done & no processing: stop worker")
			return nil
		case <-time.After(w.pollInterval):
			er := w.enqueue()
			if er != nil {
				w.logger.Errorf("processing error, continue loop: %v", er)
			}
		}
	}
}

func (w *Worker) enqueue() error {
	ctx, cancel := context.WithTimeout(context.Background(), w.iterationTimeout)
	defer cancel()

	w.logger.Info("worker tick")

	tasks, err := w.repo.GetPending(ctx)
	if err != nil {
		return fmt.Errorf("failed to get pending tasks: %w", err)
	}

	eg := &errgroup.Group{}
	for _, _task := range tasks {
		task := _task
		eg.Go(func() error {
			policy, er := w.policy.GetPluginPolicy(ctx, task.PolicyID)
			if er != nil {
				return fmt.Errorf("failed to fetch policy: %w", er)
			}

			next, er := w.interval.FromNowWhenNext(*policy)
			if er != nil {
				return fmt.Errorf("failed to compute next: %w", er)
			}

			buf, er := json.Marshal(task)
			if er != nil {
				return fmt.Errorf("failed to marshal task: %w", er)
			}

			_, er = w.client.EnqueueContext(
				ctx,
				asynq.NewTask(w.task, buf),
				asynq.MaxRetry(0),
				asynq.Timeout(5*time.Minute),
				asynq.Retention(10*time.Minute),
				asynq.Queue(w.queue),
			)
			if er != nil {
				return fmt.Errorf("failed to enqueue task: %w", er)
			}

			er = w.repo.SetNext(ctx, task.PolicyID, next)
			if er != nil {
				return fmt.Errorf("failed to set next: %w", er)
			}
			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return fmt.Errorf("failed to process tasks: %w", err)
	}

	return nil
}
