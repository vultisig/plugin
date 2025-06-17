package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntervalSchedule_ToRangeFrom(t *testing.T) {
	tests := []struct {
		name      string
		startTime time.Time
		interval  time.Duration
		ref       time.Time
		wantLast  time.Time
		wantNext  time.Time
	}{
		{
			name:      "exact match on interval",
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T10:00:00Z"),
			wantLast:  parseTime("2025-01-01T10:00:00Z"),
			wantNext:  parseTime("2025-01-01T11:00:00Z"),
		},
		{
			name:      "just after interval",
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T10:00:00.000000001Z"),
			wantLast:  parseTime("2025-01-01T10:00:00Z"),
			wantNext:  parseTime("2025-01-01T11:00:00Z"),
		},
		{
			name:      "just before interval",
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T10:59:59.999999999Z"),
			wantLast:  parseTime("2025-01-01T10:00:00Z"),
			wantNext:  parseTime("2025-01-01T11:00:00Z"),
		},
		{
			name:      "very small interval (1ns)",
			startTime: parseTime("2025-01-01T00:00:00Z"),
			ref:       parseTime("2025-01-01T00:00:01Z"),
			wantLast:  parseTime("2025-01-01T00:00:01Z"),
			wantNext:  parseTime("2025-01-01T00:00:01.000000001Z"),
		},
		{
			name:      "very large interval (1000 years)",
			startTime: parseTime("1000-01-01T00:00:00Z"),
			ref:       parseTime("2000-01-01T00:00:00Z"),
			wantLast:  parseTime("2000-01-01T00:00:00Z"),
			wantNext:  parseTime("3000-01-01T00:00:00Z"),
		},
		{
			name:      "DST transition (NY time zone)",
			startTime: parseTimeInLoc("2025-03-09T00:00:00", "America/New_York"),
			ref:       parseTimeInLoc("2025-03-09T03:30:00", "America/New_York"),
			wantLast:  parseTimeInLoc("2025-03-09T03:00:00", "America/New_York"),
			wantNext:  parseTimeInLoc("2025-03-09T04:00:00", "America/New_York"),
		},
		{
			name:      "leap year (Feb 29)",
			startTime: parseTime("2024-01-01T00:00:00Z"),
			ref:       parseTime("2024-02-29T12:00:00Z"),
			wantLast:  parseTime("2024-02-29T00:00:00Z"),
			wantNext:  parseTime("2024-03-01T00:00:00Z"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schedule := NewIntervalSchedule(tt.interval)

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

func parseTimeInLoc(s string, locName string) time.Time {
	loc, err := time.LoadLocation(locName)
	if err != nil {
		panic(err)
	}
	t, err := time.ParseInLocation("2006-01-02T15:04:05", s, loc)
	if err != nil {
		panic(err)
	}
	return t
}
