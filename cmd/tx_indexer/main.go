package main

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/vultisig/verifier/tx_indexer"
	"github.com/vultisig/verifier/tx_indexer/pkg/storage"
)

func main() {
	ctx := context.Background()

	logger := logrus.New()

	cfg, err := GetConfigure()
	if err != nil {
		panic(fmt.Errorf("GetConfigure: %w", err))
	}

	rpcs, err := tx_indexer.Rpcs(ctx, cfg.Rpc)
	if err != nil {
		panic(fmt.Errorf("tx_indexer.Rpcs: %w", err))
	}

	txIndexerStore, err := storage.NewPostgresTxIndexStore(ctx, cfg.Database.DSN)
	if err != nil {
		panic(fmt.Errorf("storage.NewPostgresTxIndexStore: %w", err))
	}

	worker := tx_indexer.NewWorker(
		logger,
		cfg.Interval,
		cfg.IterationTimeout,
		cfg.MarkLostAfter,
		cfg.Concurrency,
		txIndexerStore,
		rpcs,
	)

	err = worker.Run()
	if err != nil {
		panic(fmt.Errorf("failed to start worker: %w", err))
	}
}
