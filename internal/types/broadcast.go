package types

import "fmt"

type BroadcastStrategy string

type TransactionError struct {
	Code    string
	Message string
	Err     error
}

func (e *TransactionError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}
