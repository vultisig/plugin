package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vultisig/recipes/types"
)

func TestIntervalSchedule_ToRangeFrom(t *testing.T) {
	tests := []struct {
		name      string
		startTime time.Time
		freq      types.ScheduleFrequency
		interval  int
		ref       time.Time
		wantLast  time.Time
		wantNext  time.Time
	}{
		{
			name:      "freq daily",
			freq:      types.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY,
			interval:  1,
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-02T10:00:00Z"),
			wantLast:  parseTime("2025-01-02T00:00:00Z"),
			wantNext:  parseTime("2025-01-03T00:00:00Z"),
		},
		{
			name:      "freq weekly",
			freq:      types.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY,
			interval:  1,
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T10:00:00Z"),
			wantLast:  parseTime("2025-01-01T00:00:00Z"),
			wantNext:  parseTime("2025-01-08T00:00:00Z"),
		},
		{
			name:      "freq monthly",
			freq:      types.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY,
			interval:  1,
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T10:00:00Z"),
			wantLast:  parseTime("2025-01-01T00:00:00Z"),
			wantNext:  parseTime("2025-02-01T00:00:00Z"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schedule, err := NewIntervalSchedule(tt.freq, tt.startTime, tt.interval)
			require.NoError(t, err)

			last, next := schedule.ToRangeFrom(tt.ref)
			assert.Equal(t, tt.wantLast, last)
			assert.Equal(t, tt.wantNext, next)
		})
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}
