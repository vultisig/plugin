package payroll

import (
	"fmt"
	"time"

	"github.com/vultisig/verifier/types"
)

type Interval struct {
}

func NewSchedulerInterval() *Interval {
	return &Interval{}
}

func (i *Interval) FromNowWhenNext(policy types.PluginPolicy) (time.Time, error) {
	recipe, err := policy.GetRecipe()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to unpack recipe: %w", err)
	}

	cfg := recipe.GetConfiguration().GetFields()

	var next time.Time
	freq := cfg[frequency].GetStringValue()
	switch freq {
	case daily:
		next = time.Now().AddDate(0, 0, 1)
	case weekly:
		next = time.Now().AddDate(0, 0, 7)
	case biWeekly:
		next = time.Now().AddDate(0, 0, 14)
	case monthly:
		next = time.Now().AddDate(0, 1, 0)
	default:
		return time.Time{}, fmt.Errorf("unknown frequency: %s", freq)
	}
	return next, nil
}
