package output

import (
	"context"

	"snablr/internal/scanner"
)

type ScanCancelAware interface {
	SetCancelFunc(context.CancelFunc)
	WasCanceledByUser() bool
}

func SetCancelFunc(sink scanner.FindingSink, cancel context.CancelFunc) {
	if sink == nil || cancel == nil {
		return
	}
	if aware, ok := sink.(ScanCancelAware); ok {
		aware.SetCancelFunc(cancel)
	}
}

func WasCanceledByUser(sink scanner.FindingSink) bool {
	if sink == nil {
		return false
	}
	if aware, ok := sink.(ScanCancelAware); ok {
		return aware.WasCanceledByUser()
	}
	return false
}
