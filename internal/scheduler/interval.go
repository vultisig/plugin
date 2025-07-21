package scheduler

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
	rtypes "github.com/vultisig/recipes/types"
)

const (
	secondsInDay  = 24 * 60 * 60
	secondsInWeek = 7 * 24 * 60 * 60
)

func createSchedule(cronExpr string, frequency rtypes.ScheduleFrequency, startTime time.Time, interval int) (cron.Schedule, error) {
	if interval > 1 &&
		(frequency == rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY ||
			frequency == rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY ||
			frequency == rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY) {
		return NewIntervalSchedule(frequency, startTime, interval)
	}

	schedule, err := cron.ParseStandard(cronExpr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cron expression: %w", err)
	}

	return schedule, nil
}

func frequencyToCron(frequency rtypes.ScheduleFrequency, startTime time.Time, interval int) string {
	switch frequency {
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_UNSPECIFIED:
		return ""
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY:
		return fmt.Sprintf("%d %d * * *", startTime.Minute(), startTime.Hour())
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_HOURLY:
		if interval == 1 {
			return fmt.Sprintf("%d * * * *", startTime.Minute())
		}
		return fmt.Sprintf("%d */%d * * *", startTime.Minute(), interval)
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY:
		return fmt.Sprintf("%d %d * * %d", startTime.Minute(), startTime.Hour(), startTime.Weekday())
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY:
		return fmt.Sprintf("%d %d %d * *", startTime.Minute(), startTime.Hour(), startTime.Day())
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_BIWEEKLY:
		return fmt.Sprintf("%d %d */14 * %d", startTime.Minute(), startTime.Hour(), startTime.Weekday())
	default:
		return ""
	}
}

type IntervalSchedule struct {
	Frequency rtypes.ScheduleFrequency
	Interval  int
	StartTime time.Time
	Minute    int
	Hour      int
	Day       int
	Weekday   time.Weekday
	Location  *time.Location
}

func NewIntervalSchedule(frequency rtypes.ScheduleFrequency, startTime time.Time, interval int) (*IntervalSchedule, error) {
	if interval < 1 {
		return nil, fmt.Errorf("failed to create interval schedule: interval must be at least 1")
	}

	return &IntervalSchedule{
		Frequency: frequency,
		Interval:  interval,
		StartTime: startTime,
		Minute:    startTime.Minute(),
		Hour:      startTime.Hour(),
		Day:       startTime.Day(),
		Weekday:   startTime.Weekday(),
		Location:  startTime.Location(),
	}, nil
}

func (s *IntervalSchedule) ToRangeFrom(from time.Time) (time.Time, time.Time) {
	next := s.Next(from)

	prev := s.StartTime
	for {
		n := s.Next(prev)
		if !n.Before(next) || n.After(from) {
			break
		}
		prev = n
	}
	return prev, next
}

func (s *IntervalSchedule) Next(t time.Time) time.Time {
	t = t.In(s.Location)

	switch s.Frequency {
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_DAILY:
		return s.nextDaily(t)
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_WEEKLY:
		return s.nextWeekly(t)
	case rtypes.ScheduleFrequency_SCHEDULE_FREQUENCY_MONTHLY:
		return s.nextMonthly(t)
	default:
		return time.Time{}
	}
}

func (s *IntervalSchedule) nextDaily(t time.Time) time.Time {
	candidate := time.Date(t.Year(), t.Month(), t.Day(), s.Hour, s.Minute, 0, 0, s.Location)

	if !candidate.After(t) {
		candidate = candidate.AddDate(0, 0, 1)
	}

	startDays := int(s.StartTime.Unix() / secondsInDay)
	candidateDays := int(candidate.Unix() / secondsInDay)

	daysPastStart := candidateDays - startDays

	if daysPastStart >= 0 && daysPastStart%s.Interval == 0 {
		return candidate
	}

	daysToAdd := s.Interval - (daysPastStart % s.Interval)
	if daysPastStart < 0 {
		daysToAdd = -daysPastStart
	}

	return candidate.AddDate(0, 0, daysToAdd)
}

func (s *IntervalSchedule) nextWeekly(t time.Time) time.Time {
	daysUntilWeekday := int(s.Weekday - t.Weekday())
	if daysUntilWeekday <= 0 {
		daysUntilWeekday += 7
	}

	candidate := time.Date(
		t.Year(), t.Month(), t.Day()+daysUntilWeekday,
		s.Hour, s.Minute, 0, 0, s.Location,
	)

	if !candidate.After(t) {
		candidate = candidate.AddDate(0, 0, 7)
	}

	startWeeks := int(timeToMondayMidnight(s.StartTime).Unix() / secondsInWeek)
	candidateWeeks := int(timeToMondayMidnight(candidate).Unix() / secondsInWeek)

	weeksPastStart := candidateWeeks - startWeeks

	if weeksPastStart >= 0 && weeksPastStart%s.Interval == 0 {
		return candidate
	}

	weeksToAdd := s.Interval - (weeksPastStart % s.Interval)
	if weeksPastStart < 0 {
		weeksToAdd = -weeksPastStart
	}

	return candidate.AddDate(0, 0, 7*weeksToAdd)
}

func (s *IntervalSchedule) nextMonthly(t time.Time) time.Time {
	if t.Before(s.StartTime) {
		t = s.StartTime
	}

	startMonths := s.StartTime.Year()*12 + int(s.StartTime.Month()) - 1
	currentMonths := t.Year()*12 + int(t.Month()) - 1

	intervalsPassed := (currentMonths - startMonths) / s.Interval

	lastIntervalMonth := startMonths + intervalsPassed*s.Interval

	nextIntervalMonth := lastIntervalMonth

	if currentMonths > lastIntervalMonth ||
		(currentMonths == lastIntervalMonth &&
			(t.Day() > s.Day || (t.Day() == s.Day && (t.Hour() > s.Hour || (t.Hour() == s.Hour && t.Minute() >= s.Minute))))) {
		nextIntervalMonth = lastIntervalMonth + s.Interval
	}

	nextYear := nextIntervalMonth / 12
	nextMonth := time.Month(nextIntervalMonth%12 + 1)

	candidate := time.Date(nextYear, nextMonth, s.Day, s.Hour, s.Minute, 0, 0, s.Location)

	if candidate.Day() != s.Day {
		candidate = time.Date(nextYear, nextMonth, 0, s.Hour, s.Minute, 0, 0, s.Location)
	}

	return candidate
}

func timeToMondayMidnight(t time.Time) time.Time {
	daysFromMonday := int(t.Weekday())
	if daysFromMonday == 0 {
		daysFromMonday = 6
	} else {
		daysFromMonday--
	}

	return time.Date(t.Year(), t.Month(), t.Day()-daysFromMonday, 0, 0, 0, 0, t.Location())
}
