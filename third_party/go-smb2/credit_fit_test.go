package smb2

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/hirochachacha/go-smb2/internal/smb2"
)

// With other requests holding credits, a loan can be partial. The response
// buffer of the request must then fit the credits charged for it.
func TestOutputLengthFitsPartialCreditLoan(t *testing.T) {
	const want = 1024 * 1024
	c := &conn{capabilities: SMB2_GLOBAL_CAP_LARGE_MTU, account: openAccount(64)}
	// Three credits available, sixteen needed for a 1 MiB buffer.
	c.account.charge(2, 2)
	charge, granted, err := c.loanCredit(want, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if charge != 3 || granted != 3*64*1024 {
		t.Fatalf("charge=%d granted=%d, want a partial loan of 3 credits", charge, granted)
	}
	got := outputLengthForCredit(want, granted)
	if int(got) > int(charge)*64*1024 {
		t.Fatalf("buffer %d exceeds what %d credits cover", got, charge)
	}
	if got != uint32(granted) {
		t.Fatalf("buffer=%d, want %d", got, granted)
	}

	// A complete loan keeps the requested buffer.
	if got := outputLengthForCredit(want, want); got != want {
		t.Fatalf("complete loan changed buffer to %d", got)
	}
}

// A request the server answered with an error status (every directory listing
// ends with STATUS_NO_MORE_FILES) was granted credits by its response; the
// loan must not be returned as well. A request that got no response returns
// its loan as before.
func TestRefundCreditOnlyWithoutResponse(t *testing.T) {
	c := &conn{capabilities: SMB2_GLOBAL_CAP_LARGE_MTU, account: openAccount(128)}
	c.account.charge(15, 15) // balance 16
	charge, _, err := c.loanCredit(1024*1024, context.Background())
	if err != nil || charge != 16 {
		t.Fatalf("charge=%d err=%v, want a full 16-credit loan", charge, err)
	}
	c.account.charge(16, 16) // the response grants 16 credits

	c.refundCredit(charge, &ResponseError{Code: 0x80000006})
	if got := len(c.account.balance); got != 16 {
		t.Fatalf("balance after an answered request=%d, want 16", got)
	}
	c.refundCredit(charge, &InvalidResponseError{"broken query directory response format"})
	if got := len(c.account.balance); got != 16 {
		t.Fatalf("balance after a malformed response=%d, want 16", got)
	}
	// accept maps these statuses to os errors; they are answers too.
	for _, answered := range []error{os.ErrPermission, os.ErrNotExist, os.ErrExist} {
		c.refundCredit(charge, answered)
		if got := len(c.account.balance); got != 16 {
			t.Fatalf("balance after %v=%d, want 16", answered, got)
		}
	}
	c.refundCredit(charge, &ContextError{Err: context.DeadlineExceeded})
	if got := len(c.account.balance); got != 32 {
		t.Fatalf("balance after a request without response=%d, want the loan returned (32)", got)
	}
}

// A request with a fixed credit charge (tree connect, session setup, ...)
// spends a credit like any other: after its response grants one credit the
// balance is unchanged, not one higher.
func TestFixedChargeRequestSpendsItsCredit(t *testing.T) {
	c := &conn{account: openAccount(16)}
	if err := c.loanFixedCredit(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.account.charge(1, 1) // the response grants one credit
	if got := len(c.account.balance); got != 1 {
		t.Fatalf("balance=%d after a fixed-charge request and its response, want 1", got)
	}
	// With no credit left the loan waits, bounded by the caller's context.
	<-c.account.balance
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.loanFixedCredit(ctx); err == nil {
		t.Fatal("loan without balance did not wait for credit")
	}
}
