package smb

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestFilterAccessibleShareNamesOmitsDeniedAndSpecialSharesInStableOrder(t *testing.T) {
	shares := []string{"C$", "B", "IPC$", "A", "PRINT$", "B"}
	got, err := filterAccessibleShareNames(context.Background(), shares, func(share string) error {
		if share == "C$" || share == "B" {
			return errors.New("access denied")
		}
		return nil
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"A"}
	if names := shareNames(got); !reflect.DeepEqual(names, want) {
		t.Fatalf("accessible shares = %#v, want %#v", names, want)
	}
}

func TestFilterAccessibleShareNamesKeepsAccessibleAdministrativeShares(t *testing.T) {
	got, err := filterAccessibleShareNames(context.Background(), []string{"ADMIN$", "C$"}, func(string) error { return nil }, true)
	if err != nil {
		t.Fatal(err)
	}
	if names := shareNames(got); !reflect.DeepEqual(names, []string{"ADMIN$", "C$"}) {
		t.Fatalf("administrative shares = %#v", names)
	}
}

func TestFilterAccessibleShareNamesZeroSharesSucceeds(t *testing.T) {
	got, err := filterAccessibleShareNames(context.Background(), nil, func(string) error { return nil }, true)
	if err != nil || len(got) != 0 {
		t.Fatalf("zero shares = %#v, err=%v", got, err)
	}
}

func TestFilterAccessibleShareNamesReturnsNonPermissionFailure(t *testing.T) {
	wantErr := errors.New("transport failure")
	_, err := filterAccessibleShareNames(context.Background(), []string{"A", "B"}, func(share string) error {
		if share == "A" {
			return wantErr
		}
		return nil
	}, true)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
}

func TestFilterAccessibleShareNamesCancellationStopsValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, err := filterAccessibleShareNames(ctx, []string{"A"}, func(string) error {
		called = true
		return nil
	}, true)
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("err=%v called=%v, want cancellation before check", err, called)
	}
}

func shareNames(shares []ShareInfo) []string {
	names := make([]string, 0, len(shares))
	for _, share := range shares {
		names = append(names, share.Name)
	}
	return names
}
