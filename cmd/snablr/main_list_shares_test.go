package main

import "testing"

func TestIsListSharesInvocation(t *testing.T) {
	if !isListSharesInvocation([]string{"scan", "--targets", "server", "--list-shares"}) {
		t.Fatal("expected list-shares scan invocation")
	}
	if isListSharesInvocation([]string{"scan", "--targets", "server"}) {
		t.Fatal("did not expect normal scan invocation")
	}
	if isListSharesInvocation([]string{"discover", "--list-shares"}) {
		t.Fatal("did not expect discover invocation")
	}
}
