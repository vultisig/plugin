package types

import (
	"time"

	"github.com/google/uuid"
	rtypes "github.com/vultisig/recipes/types"
)

type TimeTriggerStatus string

const (
	StatusTimeTriggerPending TimeTriggerStatus = "PENDING"
	StatusTimeTriggerRunning TimeTriggerStatus = "RUNNING"
)

type TimeTrigger struct {
	PolicyID       uuid.UUID                `json:"policy_id"`
	CronExpression string                   `json:"cron_expression"`
	StartTime      time.Time                `json:"start_time"`
	EndTime        *time.Time               `json:"end_time"`
	Frequency      rtypes.ScheduleFrequency `json:"frequency"`
	Interval       int                      `json:"interval"`
	LastExecution  *time.Time               `json:"last_execution"`
	Status         TimeTriggerStatus        `json:"status"`
}
