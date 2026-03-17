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
