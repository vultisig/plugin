package keysign

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
	"github.com/vultisig/verifier/types"
)

type PluginEmitter struct {
	client *asynq.Client
	task   string
	queue  string
}

func NewPluginEmitter(client *asynq.Client, task, queue string) *PluginEmitter {
	return &PluginEmitter{
		client: client,
		task:   task,
		queue:  queue,
	}
}

func (e *PluginEmitter) Sign(ctx context.Context, req types.PluginKeysignRequest) error {
	buf, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	_, err = e.client.EnqueueContext(
		ctx,
		asynq.NewTask(e.task, buf),
		asynq.MaxRetry(0),
		asynq.Timeout(5*time.Minute),
		asynq.Retention(10*time.Minute),
		asynq.Queue(e.queue),
	)
	if err != nil {
		return fmt.Errorf("failed to enqueue task: %w", err)
	}
	return nil
}
