//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// A hangup reaches the process as SIGTERM, which the live TUI quits on.
func TestHangupIsForwardedAsTermination(t *testing.T) {
	terminated := make(chan os.Signal, 1)
	signal.Notify(terminated, syscall.SIGTERM)
	defer signal.Stop(terminated)

	stop := forwardHangupAsTermination()
	defer stop()

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("hangup did not end in SIGTERM")
	}
}
