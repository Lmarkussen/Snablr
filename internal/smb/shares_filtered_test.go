package smb

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Shares the scan filters reject are never connected to: the access check
// runs only for allowed shares, and the result is the same set of shares the
// unfiltered check followed by the filter would give.
func TestFilteredShareListingNeverChecksRejectedShares(t *testing.T) {
	names := []string{"Users", "ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON", "Finance", "Denied", "users", "DeploymentShare$"}
	access := func(checked *[]string) func(string) error {
		return func(share string) error {
			*checked = append(*checked, share)
			if share == "Denied" {
				return os.ErrPermission
			}
			return nil
		}
	}
	filters := map[string]func(string) bool{
		"no filters":      nil,
		"exclude admin":   func(s string) bool { return !strings.EqualFold(s, "ADMIN$") && !strings.EqualFold(s, "C$") },
		"only one share":  func(s string) bool { return strings.EqualFold(s, "Finance") },
		"only AD shares":  IsADShare,
		"excluded denied": func(s string) bool { return s != "Denied" },
	}
	for name, allow := range filters {
		var checked []string
		got, rejected, err := filterAllowedShareNames(context.Background(), names, allow, 0, access(&checked))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, share := range checked {
			if allow != nil && !allow(share) {
				t.Errorf("%s: rejected share %s was connected to", name, share)
			}
		}
		for _, share := range rejected {
			if allow == nil || allow(share) {
				t.Errorf("%s: allowed share %s reported as rejected", name, share)
			}
		}

		// Parity with the previous order: check every share, then filter.
		var all []string
		before, err := filterAccessibleShareNames(context.Background(), names, access(&all), false)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var want []ShareInfo
		for _, share := range before {
			if allow == nil || allow(share.Name) {
				want = append(want, share)
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: filtered listing %v, previous order gives %v", name, got, want)
		}
	}
}

// A transport failure on an allowed share is still reported; one on a
// rejected share cannot happen because it is never checked.
func TestFilteredShareListingKeepsCheckErrors(t *testing.T) {
	boom := errors.New("transport reset")
	_, _, err := filterAllowedShareNames(context.Background(), []string{"A", "B"}, func(s string) bool { return s == "A" }, 0, func(share string) error {
		if share == "B" {
			t.Error("rejected share B was checked")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Non-strict listing skips shares with non-permission errors, as before.
	got, _, err := filterAllowedShareNames(context.Background(), []string{"A", "B"}, nil, 0, func(share string) error {
		if share == "A" {
			return boom
		}
		return nil
	})
	if err != nil || len(got) != 1 || got[0].Name != "B" {
		t.Errorf("got %v, %v", got, err)
	}
}

// After the configured number of consecutive denials no further share is
// connected to; the untested shares are reported, not silently dropped.
func TestFilteredShareListingStopsAfterRepeatedDenials(t *testing.T) {
	var checked []string
	shares, rejected, err := filterAllowedShareNames(context.Background(), []string{"A", "D1", "D2", "D3", "E", "F"}, nil, 3, func(share string) error {
		checked = append(checked, share)
		if strings.HasPrefix(share, "D") {
			return os.ErrPermission
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"A", "D1", "D2", "D3"}; !reflect.DeepEqual(checked, want) {
		t.Errorf("checked %v, want %v", checked, want)
	}
	if len(shares) != 1 || shares[0].Name != "A" {
		t.Errorf("shares %v", shares)
	}
	if want := []string{"E", "F"}; !reflect.DeepEqual(rejected, want) {
		t.Errorf("rejected %v, want %v", rejected, want)
	}

	// An accessible share resets the count (shares are tested in name order).
	checked = nil
	_, _, _ = filterAllowedShareNames(context.Background(), []string{"D1", "D2", "E", "F1", "F2", "Z"}, nil, 3, func(share string) error {
		checked = append(checked, share)
		if strings.HasPrefix(share, "D") || strings.HasPrefix(share, "F") {
			return os.ErrPermission
		}
		return nil
	})
	if len(checked) != 6 {
		t.Errorf("checked %v, want all six", checked)
	}
}
