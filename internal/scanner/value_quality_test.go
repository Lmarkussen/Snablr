package scanner

import "testing"

func TestAssessSensitiveValueQualityRejectsPlaceholders(t *testing.T) {
	t.Parallel()

	quality := assessSensitiveValueQuality("changeme")
	if !quality.Weak || quality.Label != "low" {
		t.Fatalf("expected placeholder value to be weak, got %#v", quality)
	}
}

func TestAssessSensitiveValueQualityRejectsLowEntropyValues(t *testing.T) {
	t.Parallel()

	quality := assessSensitiveValueQuality("aaaaaaaaaaaa")
	if !quality.Weak || quality.Score > 4 {
		t.Fatalf("expected low-entropy value to be weak, got %#v", quality)
	}
}

func TestAssessSensitiveValueQualityKeepsStrongValues(t *testing.T) {
	t.Parallel()

	quality := assessSensitiveValueQuality("N9v!2qP7zL#4")
	if quality.Weak || quality.Score < 12 {
		t.Fatalf("expected strong-looking value to retain useful quality, got %#v", quality)
	}
	if quality.LengthOnly {
		t.Fatalf("strong value was marked as length-only weak, got %#v", quality)
	}
}

// TestAssessSensitiveValueQualityDistinguishesLengthOnlyWeakness keeps the
// reporting exception narrow: only shortness may be excused for an explicit
// password assignment, never placeholders or low-entropy values.
func TestAssessSensitiveValueQualityDistinguishesLengthOnlyWeakness(t *testing.T) {
	t.Parallel()

	cases := []struct {
		value      string
		lengthOnly bool
	}{
		{"8392", true},
		{"1111", true},
		{"changeme", false},
		{"example", false},
		{"aaaaaaaa", false},
	}
	for _, test := range cases {
		quality := assessSensitiveValueQuality(test.value)
		if !quality.Weak {
			t.Fatalf("expected %q to be weak, got %#v", test.value, quality)
		}
		if quality.LengthOnly != test.lengthOnly {
			t.Errorf("%q length-only = %t, want %t (%#v)", test.value, quality.LengthOnly, test.lengthOnly, quality)
		}
	}
}

func TestAssessConnectionStringQualityRejectsWeakCredentialValues(t *testing.T) {
	t.Parallel()

	quality := assessConnectionStringQuality("Server=db01;Database=Payroll;User ID=svc_payroll;Password=changeme")
	if !quality.Weak || quality.Label != "low" {
		t.Fatalf("expected placeholder connection string to be weak, got %#v", quality)
	}
}

func TestAssessConnectionStringQualityKeepsStrongCredentialValues(t *testing.T) {
	t.Parallel()

	quality := assessConnectionStringQuality("Server=db01;Database=Payroll;User ID=svc_payroll;Password=Winter2025!")
	if quality.Weak || quality.Score < 10 {
		t.Fatalf("expected plausible connection string to keep useful quality, got %#v", quality)
	}
}
