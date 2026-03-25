package output

import "snablr/internal/scanner"

type LiveProgressAware interface {
	SetTargetTotal(int)
	SetCurrentHost(string)
	MarkTargetProcessed()
	SetStatus(string)
}

func SupportsLiveProgress(sink scanner.FindingSink) bool {
	if sink == nil {
		return false
	}
	_, ok := sink.(LiveProgressAware)
	return ok
}

func SetTargetTotal(sink scanner.FindingSink, total int) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(LiveProgressAware); ok {
		aware.SetTargetTotal(total)
	}
}

func SetCurrentHost(sink scanner.FindingSink, host string) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(LiveProgressAware); ok {
		aware.SetCurrentHost(host)
	}
}

func MarkTargetProcessed(sink scanner.FindingSink) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(LiveProgressAware); ok {
		aware.MarkTargetProcessed()
	}
}

func SetStatus(sink scanner.FindingSink, status string) {
	if sink == nil {
		return
	}
	if aware, ok := sink.(LiveProgressAware); ok {
		aware.SetStatus(status)
	}
}
