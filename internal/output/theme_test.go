package output

import (
	"bytes"
	"strings"
	"testing"
)

func renderThemeReport(t *testing.T) string {
	t.Helper()
	var report bytes.Buffer
	writer, err := NewHTMLWriter(&report, nil)
	if err != nil {
		t.Fatalf("NewHTMLWriter returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	return report.String()
}

func TestHTMLReportThemesAreStandaloneAndDarkByDefault(t *testing.T) {
	report := renderThemeReport(t)
	checks := []string{
		`<html lang="en" data-theme="dark">`,
		`data-theme-choice="dark"`,
		`data-theme-choice="flashbang"`,
		`aria-pressed="true">Dark</button>`,
		`>Flashbang</button>`,
		`:root[data-theme="flashbang"]`,
		`--accent: #3b82f6`,
		`--surface-table-head`,
		`details.group[open]`,
		`.nav-chips a:hover`,
		`.meta-chip`,
		`sessionStorage`,
		`snablr-report-theme:`,
	}
	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report is missing theme marker %q", check)
		}
	}
	for _, external := range []string{"https://", "http://", "<link rel=\"stylesheet\""} {
		if strings.Contains(report, external) {
			t.Errorf("standalone report unexpectedly references external resource %q", external)
		}
	}
}

func TestHTMLReportThemeScriptDoesNotReloadOrReplaceReportContent(t *testing.T) {
	report := renderThemeReport(t)
	if strings.Contains(report, "location.reload") || strings.Contains(report, "document.body.innerHTML") {
		t.Fatal("theme switching must not reload or replace report content")
	}
	if !strings.Contains(report, "input.addEventListener(\"input\", applyFilter)") {
		t.Fatal("existing filter interaction is missing from themed report")
	}
	if !strings.Contains(report, "applyTheme(button.getAttribute(\"data-theme-choice\"), true)") {
		t.Fatal("theme buttons are not wired to in-place theme switching")
	}
}
