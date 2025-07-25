package scheduler

import (
	"time"

	"github.com/vultisig/verifier/types"
)

type Interval interface {
	FromNowWhenNext(policy types.PluginPolicy) (time.Time, error)
}
