package credentialanalysis

import "testing"

const dualPathValue = "Norsk-Hemmelig-123!"

// findingDerivedReview mirrors the record produced by the post-scan fallback for
// a content finding: it knows the value and the member path, but no identity.
func findingDerivedReview(value, path string) Candidate {
	return Candidate{
		Verification:    Review,
		CredentialType:  "password",
		Value:           value,
		Path:            path,
		ValidationBasis: "credential_like_value_without_conclusive_identity_association",
		ReviewReasons:   []string{"credential-like value extracted but identity association could not be conclusively established"},
		Evidence: []Evidence{{
			RuleID: "content.password_assignment_indicators",
			Path:   path,
		}},
	}
}

// structuredConfirmed mirrors the record produced by the shared harvester for a
// reconstructed Office record.
func structuredConfirmed(value, identity, domain, path string) Candidate {
	return Candidate{
		Verification:    Confirmed,
		CredentialType:  "password",
		Identity:        identity,
		Domain:          domain,
		Value:           value,
		Path:            path,
		ValidationBasis: "structured configuration section",
		Evidence:        []Evidence{{Path: path}},
	}
}

// TestDualPathReviewMergesIntoConfirmedSameSource is the core blocker: the same
// logical credential reported by both evidence paths must yield one Confirmed
// record, never a Confirmed plus a Review copy.
func TestDualPathReviewMergesIntoConfirmedSameSource(t *testing.T) {
	const path = "norwegian-docx-pair.docx!word/document.xml"
	report := Analyze([]Candidate{
		findingDerivedReview(dualPathValue, path),
		structuredConfirmed(dualPathValue, "svc_backup", "KUNDE", path),
	})
	if len(report.Confirmed) != 1 || len(report.Review) != 0 {
		t.Fatalf("expected exactly one Confirmed record, got confirmed=%d review=%d", len(report.Confirmed), len(report.Review))
	}
	if len(report.Candidates) != 1 {
		t.Fatalf("expected one logical record, got %d", len(report.Candidates))
	}
	if report.DuplicatesMerged != 1 {
		t.Fatalf("expected one merge to be reported, got %d", report.DuplicatesMerged)
	}
	record := report.Candidates[0]
	if record.Verification != Confirmed {
		t.Fatalf("verification = %q, want confirmed", record.Verification)
	}
	if record.Identity != "svc_backup" || record.Domain != "KUNDE" {
		t.Fatalf("identity/domain metadata lost: %#v", record)
	}
	if record.ValidationBasis != "structured configuration section" {
		t.Fatalf("validation basis = %q, want the strongest basis", record.ValidationBasis)
	}
}

// TestDualPathReviewMergesIntoConfirmedCompatibleIdentity covers the variant
// where the finding record already carries an identity but no domain.
func TestDualPathReviewMergesIntoConfirmedCompatibleIdentity(t *testing.T) {
	const path = "credentials.xlsx!xl/worksheets/sheet1.xml"
	review := findingDerivedReview(dualPathValue, path)
	review.Identity = "svc_backup"
	report := Analyze([]Candidate{
		review,
		structuredConfirmed(dualPathValue, "svc_backup", "KUNDE", path),
	})
	if len(report.Confirmed) != 1 || len(report.Review) != 0 {
		t.Fatalf("expected exactly one Confirmed record, got confirmed=%d review=%d", len(report.Confirmed), len(report.Review))
	}
	if report.Candidates[0].Domain != "KUNDE" {
		t.Fatalf("domain metadata lost: %#v", report.Candidates[0])
	}
}

// TestDistinctPasswordsForSameIdentityArePreserved guards against over-merging.
func TestDistinctPasswordsForSameIdentityArePreserved(t *testing.T) {
	report := Analyze([]Candidate{
		structuredConfirmed("First-Password-1!", "svc_backup", "KUNDE", "doc.docx!word/document.xml"),
		structuredConfirmed("Second-Password-2!", "svc_backup", "KUNDE", "doc.docx!word/document.xml"),
	})
	if len(report.Candidates) != 2 {
		t.Fatalf("expected two distinct records, got %d: %#v", len(report.Candidates), report.Candidates)
	}
}

// TestSameValueDifferentIdentitiesArePreserved guards against collapsing two
// accounts that happen to share a password.
func TestSameValueDifferentIdentitiesArePreserved(t *testing.T) {
	report := Analyze([]Candidate{
		structuredConfirmed("Shared-Password-9!", "svc_one", "KUNDE", "doc.docx!word/document.xml"),
		structuredConfirmed("Shared-Password-9!", "svc_two", "KUNDE", "doc.docx!word/document.xml"),
	})
	if len(report.Candidates) != 2 {
		t.Fatalf("expected two distinct records, got %d: %#v", len(report.Candidates), report.Candidates)
	}
}

// TestSameValueDifferentOriginsArePreserved keeps material from unrelated
// documents apart while still allowing same-file dual paths to merge.
func TestSameValueDifferentOriginsArePreserved(t *testing.T) {
	report := Analyze([]Candidate{
		findingDerivedReview("Shared-Password-9!", "notes-a.txt"),
		findingDerivedReview("Shared-Password-9!", "notes-b.txt"),
	})
	if len(report.Candidates) != 2 {
		t.Fatalf("expected two records for unrelated origins, got %d: %#v", len(report.Candidates), report.Candidates)
	}
}

// TestMergedRecordPreservesAllEvidence verifies weaker evidence is retained.
func TestMergedRecordPreservesAllEvidence(t *testing.T) {
	const path = "passordliste.docx!word/document.xml"
	review := findingDerivedReview(dualPathValue, path)
	review.Evidence = append(review.Evidence, Evidence{RuleID: "filename.norwegian_password_list_keywords", Path: "passordliste.docx"})
	report := Analyze([]Candidate{
		review,
		structuredConfirmed(dualPathValue, "svc_word", "", path),
	})
	if len(report.Candidates) != 1 {
		t.Fatalf("expected one merged record, got %d", len(report.Candidates))
	}
	record := report.Candidates[0]
	paths := map[string]bool{}
	ruleIDs := map[string]bool{}
	for _, evidence := range record.Evidence {
		paths[evidence.Path] = true
		if evidence.RuleID != "" {
			ruleIDs[evidence.RuleID] = true
		}
	}
	if !ruleIDs["content.password_assignment_indicators"] || !ruleIDs["filename.norwegian_password_list_keywords"] {
		t.Fatalf("rule evidence lost during merge: %#v", record.Evidence)
	}
	if !paths[path] || !paths["passordliste.docx"] {
		t.Fatalf("path evidence lost during merge: %#v", record.Evidence)
	}
	if record.ReviewReasons != nil {
		t.Fatalf("confirmed record kept review reasons: %#v", record.ReviewReasons)
	}
}

// TestDualPathMergeIsOrderIndependent ensures a Review record arriving after the
// Confirmed record merges the same way.
func TestDualPathMergeIsOrderIndependent(t *testing.T) {
	const path = "norwegian-docx-pair.docx!word/document.xml"
	reversed := Analyze([]Candidate{
		structuredConfirmed(dualPathValue, "svc_backup", "KUNDE", path),
		findingDerivedReview(dualPathValue, path),
	})
	if len(reversed.Confirmed) != 1 || len(reversed.Review) != 0 || len(reversed.Candidates) != 1 {
		t.Fatalf("reverse order did not merge: confirmed=%d review=%d total=%d", len(reversed.Confirmed), len(reversed.Review), len(reversed.Candidates))
	}
}

// TestLogicalOriginNormalizesSeparators documents the normalization helper used
// for provenance comparison.
func TestLogicalOriginNormalizesSeparators(t *testing.T) {
	for _, test := range []struct{ path, want string }{
		{"document.docx!word/document.xml", "document.docx"},
		{`document.docx!word\document.xml`, "document.docx"},
		{"plain/path.txt", "plain/path.txt"},
		// UNC input is normalized for comparison only; display formatting is
		// handled by the reporting layer.
		{`\\fs01\share\document.docx!word/document.xml`, "fs01/share/document.docx"},
	} {
		if got := logicalOrigin(test.path); got != test.want {
			t.Errorf("logicalOrigin(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}
