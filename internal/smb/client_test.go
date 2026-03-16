package smb

import (
	"errors"
	"net"
	"testing"
)

func TestIsIgnorableCloseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "net err closed", err: net.ErrClosed, want: true},
		{name: "closed network connection", err: errors.New("write tcp 127.0.0.1:445->127.0.0.1:40000: use of closed network connection"), want: true},
		{name: "already closed", err: errors.New("connection already closed"), want: true},
		{name: "real error", err: errors.New("permission denied"), want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isIgnorableCloseError(tt.err); got != tt.want {
				t.Fatalf("isIgnorableCloseError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
