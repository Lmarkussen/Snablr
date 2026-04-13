package main

import (
	"flag"
	"testing"
)

func TestOptionalBoolFlagDistinguishesUnsetFromExplicitFalse(t *testing.T) {
	t.Parallel()

	var value optionalBoolFlag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&value, "wim-enabled", "")

	if err := fs.Parse([]string{"--wim-enabled=false"}); err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	ptr := value.ptr()
	if ptr == nil || *ptr {
		t.Fatalf("expected explicit false bool flag, got %#v", ptr)
	}
}

func TestOptionalInt64FlagRecordsExplicitOverride(t *testing.T) {
	t.Parallel()

	var value optionalInt64Flag
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.Var(&value, "wim-max-size", "")

	if err := fs.Parse([]string{"--wim-max-size", "536870912"}); err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	ptr := value.ptr()
	if ptr == nil || *ptr != 536870912 {
		t.Fatalf("expected explicit int64 override, got %#v", ptr)
	}
}
