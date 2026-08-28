package systemkey

import (
	"bytes"
	"errors"
	"testing"

	"snablr/internal/registryhive"
	"snablr/internal/registryhive/testfixture"
)

func fragments(prefix string) map[string]string {
	return map[string]string{
		"JD":    prefix,
		"Skew1": "22334455",
		"GBG":   "66778899",
		"Data":  "aabbccdd",
	}
}

func open(t *testing.T, spec testfixture.Spec) *registryhive.Reader {
	t.Helper()
	b := testfixture.Build(spec)
	hive, err := registryhive.Open(bytes.NewReader(b), int64(len(b)), registryhive.Options{})
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	return hive
}

func TestDeriveControlSetOne(t *testing.T) {
	current := uint32(1)
	hive := open(t, testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")})
	r, err := Derive(hive)
	if err != nil {
		t.Fatal(err)
	}
	if r.ControlSet != 1 {
		t.Fatalf("control set=%d", r.ControlSet)
	}
	want := [16]byte{0x66, 0x33, 0x22, 0x22, 0x99, 0x77, 0xbb, 0x33, 0x00, 0x44, 0x11, 0xaa, 0xcc, 0x88, 0xdd, 0x55}
	if r.BootKey != want {
		t.Fatalf("unexpected boot-key result")
	}
}

func TestDeriveControlSetTwo(t *testing.T) {
	current := uint32(2)
	spec := testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeControl2: true, IncludeLSA: true, Fragments: fragments("00112233"), Fragments2: fragments("ffeeddcc")}
	r, err := Derive(open(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	if r.ControlSet != 2 {
		t.Fatalf("control set=%d", r.ControlSet)
	}
	// The second set has a distinct JD fragment, proving ControlSet001 was not selected.
	want := [16]byte{0x66, 0x33, 0x22, 0xdd, 0x99, 0x77, 0xbb, 0xcc, 0xff, 0x44, 0xee, 0xaa, 0xcc, 0x88, 0xdd, 0x55}
	if r.BootKey != want {
		t.Fatalf("unexpected control-set-two boot-key result")
	}
}

func TestDeriveNormalizesPathsThroughRegistryHive(t *testing.T) {
	current := uint32(1)
	hive := open(t, testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")})
	key, err := hive.OpenKey(`controlset001/control/LSA/jd`)
	if err != nil {
		t.Fatal(err)
	}
	class, err := key.ClassName()
	if err != nil || class != "00112233" {
		t.Fatalf("class=%q err=%v", class, err)
	}
}

func TestDeriveErrors(t *testing.T) {
	current := uint32(1)
	cases := []struct {
		name string
		spec testfixture.Spec
		want error
	}{
		{"missing-select", testfixture.Spec{IncludeControl: true}, ErrMissingSelect},
		{"missing-current", testfixture.Spec{IncludeSelect: true, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")}, ErrMissingCurrent},
		{"bad-current-type", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, CurrentType: registryhive.RegSZ, CurrentRaw: []byte{1, 0, 0, 0}, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")}, ErrInvalidCurrent},
		{"zero-current", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: uintPtr(0), IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")}, ErrInvalidCurrent},
		{"large-current", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: uintPtr(1000), IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")}, ErrInvalidCurrent},
		{"missing-control", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current}, ErrMissingControlSet},
		{"missing-control-key", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControlSet: true}, ErrMissingControl},
		{"missing-lsa", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true}, ErrMissingLSA},
		{"missing-jd", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrMissingFragment},
		{"missing-skew1", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00112233", "GBG": "66778899", "Data": "aabbccdd"}}, ErrMissingFragment},
		{"missing-gbg", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "Data": "aabbccdd"}}, ErrMissingFragment},
		{"missing-data", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00112233", "Skew1": "22334455", "GBG": "66778899"}}, ErrMissingFragment},
		{"empty-class", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrMissingClass},
		{"odd-length", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "0", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrInvalidFragment},
		{"bad-hex", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "00xx", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrInvalidFragment},
		{"too-short", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "0011", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrInvalidFragment},
		{"too-long", testfixture.Spec{IncludeSelect: true, IncludeCurrent: true, Current: &current, IncludeControl: true, IncludeLSA: true, Fragments: map[string]string{"JD": "0011223344", "Skew1": "22334455", "GBG": "66778899", "Data": "aabbccdd"}}, ErrInvalidFragment},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := derive(open(t, tc.spec))
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
}

func derive(hive *registryhive.Reader) error { _, err := Derive(hive); return err }
func uintPtr(v uint32) *uint32               { return &v }

func TestDeriveMalformedHiveDoesNotPanic(t *testing.T) {
	current := uint32(1)
	b := testfixture.Build(testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")})
	b[0] = 'x'
	if _, err := registryhive.Open(bytes.NewReader(b), int64(len(b)), registryhive.Options{}); err == nil {
		t.Fatal("expected malformed hive")
	}
}

func FuzzDerive(f *testing.F) {
	current := uint32(1)
	f.Add(testfixture.Build(testfixture.Spec{Current: &current, IncludeSelect: true, IncludeCurrent: true, IncludeControl: true, IncludeLSA: true, Fragments: fragments("00112233")}))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if recover() != nil {
				t.Fatalf("panic")
			}
		}()
		hive, err := registryhive.Open(bytes.NewReader(data), int64(len(data)), registryhive.Options{})
		if err == nil {
			_, _ = Derive(hive)
		}
	})
}
