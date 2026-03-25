package seed

import (
	"archive/zip"
	"bytes"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"snablr/internal/rules"
	"snablr/internal/scanner"
	"snablr/internal/wiminspect"
	"snablr/pkg/logx"
)

func TestGenerateRespectsScaleDepthAndExpectedSignals(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 4,
		MaxFiles:         50,
		Depth:            2,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(files) != 50 {
		t.Fatalf("expected 50 files, got %d", len(files))
	}

	foundNested := false
	foundSignals := false
	uniqueFilenames := make(map[string]struct{})
	for _, file := range files {
		if len(file.ExpectedSignalTypes) > 0 {
			foundSignals = true
		}
		if file.RelativePath != "" && file.RelativePath != "SnablrLab" {
			foundNested = true
		}
		uniqueFilenames[file.Filename] = struct{}{}
	}
	if !foundNested {
		t.Fatalf("expected nested relative paths in generated files")
	}
	if !foundSignals {
		t.Fatalf("expected generated files to include expected signal types")
	}
	if len(uniqueFilenames) < 10 {
		t.Fatalf("expected diverse generated filenames, got %d unique names", len(uniqueFilenames))
	}
}

func TestGenerateSupportsIntentAndSignalTuning(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory:    2,
		MaxFiles:            20,
		SeedPrefix:          "SnablrLab",
		RandomSeed:          20260316,
		LikelyHitRatio:      0,
		FilenameOnlyRatio:   100,
		HighSeverityRatio:   0,
		MediumSeverityRatio: 100,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("expected generated files")
	}

	foundPossibleOrNoise := false
	foundFilenameOnly := false
	foundMedium := false

	for _, file := range files {
		if file.IntendedAs == "possible-hit" || file.IntendedAs == "filler/noise" {
			foundPossibleOrNoise = true
		}
		hasContentSignal := false
		for _, signalType := range file.ExpectedSignalTypes {
			if signalType == "content" {
				hasContentSignal = true
				break
			}
		}
		if !hasContentSignal {
			foundFilenameOnly = true
		}
		if file.ExpectedSeverity == "medium" {
			foundMedium = true
		}
	}

	if !foundPossibleOrNoise {
		t.Fatalf("expected tuned generation to include non-likely files")
	}
	if !foundFilenameOnly {
		t.Fatalf("expected tuned generation to include filename-only variants")
	}
	if !foundMedium {
		t.Fatalf("expected tuned generation to include medium severity variants")
	}
}

func TestGenerateProducesUniquePathsAtLargerScale(t *testing.T) {
	t.Parallel()

	categoryCount := len(defaultTemplates())
	files, err := Generate(GenerateOptions{
		CountPerCategory: 25,
		MaxFiles:         500,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	expected := categoryCount * 25
	if expected > 500 {
		expected = 500
	}
	if len(files) != expected {
		t.Fatalf("expected %d files, got %d", expected, len(files))
	}

	seen := make(map[string]struct{}, len(files))
	for _, file := range files {
		fullPath := FullPath(file)
		if _, ok := seen[fullPath]; ok {
			t.Fatalf("expected unique generated paths, found duplicate %s", fullPath)
		}
		seen[fullPath] = struct{}{}
	}
}

func TestGenerateDatabaseSeedPackIncludesMixedExpectedClasses(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         400,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	triageClasses := make(map[string]int)
	detectionClasses := make(map[string]int)
	foundDatabaseCategory := false
	foundActionableConfig := false
	foundConfigOnly := false
	foundWeakReview := false
	foundArtifact := false
	foundCorrelated := false

	for _, file := range files {
		if file.Category != "database" {
			continue
		}
		foundDatabaseCategory = true
		if file.ExpectedClass != "" {
			detectionClasses[file.ExpectedClass]++
		}
		if file.ExpectedTriageClass != "" {
			triageClasses[file.ExpectedTriageClass]++
		}
		name := strings.ToLower(file.Filename)
		switch {
		case name == "appsettings.json" || name == "web.config" || name == ".env" || strings.HasSuffix(name, ".dsn"):
			if file.ExpectedClass == seedClassActionable || file.ExpectedClass == seedClassCorrelatedHighConfidence {
				foundActionableConfig = true
			}
		case name == "database.yml" || name == "application.properties" || name == "config.php" || name == "k8s-db-secret.yaml":
			if file.ExpectedClass == seedClassConfigOnly {
				foundConfigOnly = true
			}
		case name == "db-admin-notes.txt" || name == "deploy-db.py":
			if file.ExpectedClass == seedClassWeakReview {
				foundWeakReview = true
			}
		case strings.HasSuffix(name, ".bak") || strings.HasSuffix(name, ".dump") || strings.HasSuffix(name, ".dmp") || strings.HasSuffix(name, ".sqlite") || strings.HasSuffix(name, ".mdb"):
			if file.ExpectedClass == seedClassActionable {
				foundArtifact = true
			}
		case name == "docker-compose.yml" || name == "odbc.ini":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated && file.ExpectedConfidence == "high" {
				foundCorrelated = true
			}
		}
	}

	if !foundDatabaseCategory {
		t.Fatal("expected generated corpus to include database category files")
	}
	for _, expected := range []string{seedClassConfigOnly, seedClassWeakReview, seedClassActionable, seedClassCorrelatedHighConfidence} {
		if detectionClasses[expected] == 0 {
			t.Fatalf("expected database seed pack to include detection class %q, got %+v", expected, detectionClasses)
		}
	}
	for _, expected := range []string{seedTriageActionable, seedTriageConfigOnly, seedTriageWeakReview} {
		if triageClasses[expected] == 0 {
			t.Fatalf("expected database seed pack to include triage class %q, got %+v", expected, triageClasses)
		}
	}
	if !foundActionableConfig {
		t.Fatalf("expected actionable database configuration samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundConfigOnly {
		t.Fatalf("expected config-only database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundWeakReview {
		t.Fatalf("expected weak-review database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundArtifact {
		t.Fatalf("expected database artifact or backup samples, got %+v / %+v", detectionClasses, triageClasses)
	}
	if !foundCorrelated {
		t.Fatalf("expected correlated high-confidence database samples, got %+v / %+v", detectionClasses, triageClasses)
	}
}

func TestGenerateSecretStoreSeedPackIncludesActionableArtifacts(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 12,
		MaxFiles:         600,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundNTDS := false
	foundShadow := false
	foundSystem := false
	foundSecurity := false
	foundNTDSBackup := false
	foundHiveBackup := false
	foundDecoy := false

	for _, file := range files {
		if file.Category != "secret-stores" {
			continue
		}
		name := strings.ToLower(file.Filename)
		switch name {
		case "ntds.dit":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundNTDS = true
			}
		case "ntds.dit.bak":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundNTDSBackup = true
			}
		case "shadow":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundShadow = true
			}
		case "system":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSystem = true
			}
		case "security":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSecurity = true
			}
		case "system.bak":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundHiveBackup = true
			}
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		case "security.old":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundHiveBackup = true
			}
		case "shadow-notes.txt":
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		case "system.txt":
			if file.IntendedAs == "filler/noise" {
				foundDecoy = true
			}
		}
	}

	if !foundNTDS {
		t.Fatal("expected secret-store seed pack to include actionable NTDS.DIT artifact")
	}
	if !foundShadow {
		t.Fatal("expected secret-store seed pack to include actionable shadow artifact")
	}
	if !foundSystem {
		t.Fatal("expected secret-store seed pack to include actionable SYSTEM hive artifact")
	}
	if !foundSecurity {
		t.Fatal("expected secret-store seed pack to include actionable SECURITY hive artifact")
	}
	if !foundNTDSBackup {
		t.Fatal("expected secret-store seed pack to include actionable NTDS.DIT.bak artifact")
	}
	if !foundHiveBackup {
		t.Fatal("expected secret-store seed pack to include actionable hive backup artifact")
	}
	if !foundDecoy {
		t.Fatal("expected secret-store seed pack to include benign decoys")
	}
}

func TestGenerateAWSSeedPackIncludesPrimaryAndSupportingArtifacts(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 8,
		MaxFiles:         260,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCreds := false
	foundConfig := false
	foundCorrelated := false
	for _, file := range files {
		if file.Category != "aws-artifacts" && file.Category != "aws-correlation" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "credentials", "credentials.bak":
			if file.ExpectedClass == seedClassActionable || file.ExpectedClass == seedClassCorrelatedHighConfidence {
				foundCreds = true
			}
		case "config", "config.bak":
			if file.ExpectedTriageClass == seedTriageWeakReview {
				foundConfig = true
			}
		}
		if file.Category == "aws-correlation" && file.ExpectedCorrelated && file.ExpectedClass == seedClassCorrelatedHighConfidence {
			foundCorrelated = true
		}
	}

	if !foundCreds {
		t.Fatal("expected actionable AWS credentials seeds")
	}
	if !foundConfig {
		t.Fatal("expected supporting AWS config seeds")
	}
	if !foundCorrelated {
		t.Fatal("expected correlated AWS seed pack")
	}
}

func TestGenerateADCorrelationSeedPackIncludesCorrelatedAnchor(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 12,
		MaxFiles:         320,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260316,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCorrelatedNTDS := false
	foundSupportingSystem := false

	for _, file := range files {
		if file.Category != "ad-correlation" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "ntds.dit":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated && file.ExpectedConfidence == "high" {
				foundCorrelatedNTDS = true
			}
		case "system":
			if file.ExpectedClass == seedClassActionable && file.ExpectedTriageClass == seedTriageActionable {
				foundSupportingSystem = true
			}
		}
	}

	if !foundCorrelatedNTDS {
		t.Fatal("expected ad-correlation seed pack to include correlated NTDS.DIT anchor")
	}
	if !foundSupportingSystem {
		t.Fatal("expected ad-correlation seed pack to include supporting SYSTEM artifact")
	}
}

func TestGeneratePrivateKeySeedPackIncludesHighSignalAndSupportArtifacts(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260323,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundPrivateKey := false
	foundPPK := false
	foundOVPN := false
	foundSupport := false
	foundCorrelated := false

	for _, file := range files {
		switch file.Category {
		case "private-keys":
			switch strings.ToLower(file.Filename) {
			case "id_rsa", "id_ed25519", "identity":
				if file.ExpectedClass == seedClassActionable && file.ExpectedConfidence == "high" {
					foundPrivateKey = true
				}
			case "client-admin.ppk":
				if file.ExpectedClass == seedClassActionable {
					foundPPK = true
				}
			case "branch-admin.ovpn":
				if file.ExpectedClass == seedClassActionable {
					foundOVPN = true
				}
			case "authorized_keys", "known_hosts":
				if file.ExpectedClass == seedClassWeakReview {
					foundSupport = true
				}
			}
		case "private-key-correlation":
			if strings.EqualFold(file.Filename, "id_rsa") && file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated {
				foundCorrelated = true
			}
		}
	}

	if !foundPrivateKey {
		t.Fatal("expected private key seed pack to include actionable extensionless private key artifacts")
	}
	if !foundPPK {
		t.Fatal("expected private key seed pack to include actionable .ppk artifacts")
	}
	if !foundOVPN {
		t.Fatal("expected private key seed pack to include actionable .ovpn artifacts")
	}
	if !foundSupport {
		t.Fatal("expected private key seed pack to include lower-priority SSH support artifacts")
	}
	if !foundCorrelated {
		t.Fatal("expected private key correlation seed pack to include correlated high-confidence anchor")
	}
}

func TestGenerateWindowsCredentialStoreSeedPackIncludesStandaloneAndCorrelatedCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260324,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCredentials := false
	foundVault := false
	foundProtect := false
	foundCorrelated := false
	foundBackupVariant := false

	for _, file := range files {
		switch file.Category {
		case "windows-credential-stores":
			path := FullPath(file)
			switch strings.ToLower(file.Filename) {
			case "a1b2c3d4":
				if file.ExpectedClass == seedClassActionable && strings.Contains(strings.ToLower(path), "/microsoft/credentials/") {
					foundCredentials = true
				}
			case "policy.vpol":
				if file.ExpectedClass == seedClassActionable && strings.Contains(strings.ToLower(path), "/microsoft/vault/") {
					foundVault = true
				}
			case "preferred":
				if file.ExpectedClass == seedClassActionable && strings.Contains(strings.ToLower(path), "/microsoft/protect/") {
					foundProtect = true
				}
			}
			if strings.Contains(strings.ToLower(path), "archive/profilecopies/") || strings.Contains(strings.ToLower(path), "backups/usermigrations/") {
				foundBackupVariant = true
			}
		case "windows-credential-correlation":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && strings.Contains(strings.ToLower(FullPath(file)), "/microsoft/credentials/") && file.ExpectedCorrelated {
				foundCorrelated = true
			}
		}
	}

	if !foundCredentials || !foundVault || !foundProtect {
		t.Fatalf("expected windows credential-store seed pack to include credentials, vault, and protect samples")
	}
	if !foundCorrelated {
		t.Fatal("expected windows credential-store correlation seed pack to include correlated anchor")
	}
	if !foundBackupVariant {
		t.Fatal("expected windows credential-store seed pack to include backup or migrated profile variants")
	}
}

func TestGenerateBackupExposureSeedPackIncludesStandaloneAndCorrelatedCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260326,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundWindowsImageBackup := false
	foundSystemVolumeInfo := false
	foundRegBack := false
	foundCorrelated := false
	foundNegative := false

	for _, file := range files {
		switch file.Category {
		case "backup-exposure":
			path := strings.ToLower(FullPath(file))
			if file.ExpectedClass == seedClassActionable && strings.Contains(path, "/windowsimagebackup/") {
				foundWindowsImageBackup = true
			}
			if file.ExpectedClass == seedClassActionable && strings.Contains(path, "/system volume information/") {
				foundSystemVolumeInfo = true
			}
			if file.ExpectedClass == seedClassActionable && strings.Contains(path, "/regback/") {
				foundRegBack = true
			}
			if strings.Contains(path, "/windowsimagebackup-notes/") && file.IntendedAs == "filler/noise" {
				foundNegative = true
			}
		case "backup-exposure-correlation":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated && strings.Contains(strings.ToLower(FullPath(file)), "ntds.dit.bak") {
				foundCorrelated = true
			}
		}
	}

	if !foundWindowsImageBackup || !foundSystemVolumeInfo || !foundRegBack {
		t.Fatal("expected backup-exposure seed pack to include WindowsImageBackup, System Volume Information, and RegBack cases")
	}
	if !foundCorrelated {
		t.Fatal("expected backup-exposure correlation seed pack to include a correlated high-confidence anchor")
	}
	if !foundNegative {
		t.Fatal("expected backup-exposure seed pack to include a negative near-miss path")
	}
}

func TestGenerateBrowserCredentialStoreSeedPackIncludesWeakAndCorrelatedCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260327,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundFirefox := false
	foundFirefoxKey := false
	foundChromium := false
	foundChromiumCookie := false
	foundCorrelated := false
	foundNegative := false

	for _, file := range files {
		switch file.Category {
		case "browser-credential-stores":
			path := strings.ToLower(FullPath(file))
			switch strings.ToLower(file.Filename) {
			case "logins.json":
				if file.ExpectedClass == seedClassWeakReview && strings.Contains(path, "/mozilla/firefox/profiles/") {
					foundFirefox = true
				}
			case "key4.db":
				if file.ExpectedClass == seedClassWeakReview && strings.Contains(path, "/mozilla/firefox/profiles/") {
					foundFirefoxKey = true
				}
			case "login data":
				if file.ExpectedClass == seedClassWeakReview && strings.Contains(path, "/user data/") {
					foundChromium = true
				}
			case "cookies":
				if file.ExpectedClass == seedClassWeakReview && strings.Contains(path, "/user data/") {
					foundChromiumCookie = true
				}
			}
			if (strings.HasSuffix(path, "/login data.txt") || strings.HasSuffix(path, "/logins.json.bak")) && file.IntendedAs == "filler/noise" {
				foundNegative = true
			}
		case "browser-credential-correlation":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated &&
				(strings.EqualFold(file.Filename, "logins.json") || strings.EqualFold(file.Filename, "Login Data")) {
				foundCorrelated = true
			}
		}
	}

	if !foundFirefox || !foundFirefoxKey || !(foundChromium || foundChromiumCookie) {
		t.Fatal("expected browser credential-store seed pack to include Firefox and Chromium credential artifacts")
	}
	if !foundCorrelated {
		t.Fatal("expected browser credential-store correlation seed pack to include a correlated high-confidence anchor")
	}
	if !foundNegative {
		t.Fatal("expected browser credential-store seed pack to include negative near-miss artifacts")
	}
}

func TestGenerateSQLiteSeedPackIncludesPositiveNegativeAndCorrelatedCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCredentialDB := false
	foundTokenDB := false
	foundBenignDB := false
	foundCorrelated := false

	for _, file := range files {
		switch file.Category {
		case "sqlite-databases":
			switch strings.ToLower(file.Filename) {
			case "customers-prod.sqlite":
				if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "::users.password") {
					foundCredentialDB = true
				}
			case "session-store.db":
				if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "::sessions.token") {
					foundTokenDB = true
				}
			case "telemetry-cache.db":
				if file.ExpectedClass == seedClassConfigOnly {
					foundBenignDB = true
				}
			}
		case "sqlite-correlation":
			if strings.EqualFold(file.Filename, "payroll-cache.sqlite3") && file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedCorrelated {
				foundCorrelated = true
			}
		}
	}

	if !foundCredentialDB || !foundTokenDB || !foundBenignDB {
		t.Fatal("expected sqlite seed pack to include actionable credential dbs and a benign negative case")
	}
	if !foundCorrelated {
		t.Fatal("expected sqlite correlation seed pack to include a correlated high-confidence sqlite anchor")
	}
}

func TestGenerateZIPSeedPackIncludesPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCorrelated := false
	foundActionable := false
	foundConfigOnly := false
	foundPrivateKeyBundle := false
	foundWinCredBundle := false
	foundBinaryNoise := false
	foundNestedNoise := false
	foundOversized := false

	for _, file := range files {
		if file.Category != "zip-archives" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "deploy-package.zip":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && file.ExpectedPath == "SnablrLab/Deploy/deploy-package.zip!.env" {
				foundCorrelated = true
			}
		case "legacy-configs.zip", "deployment-recovery.zip":
			if file.ExpectedClass == seedClassActionable && strings.Contains(file.ExpectedPath, ".zip!") {
				foundActionable = true
			}
		case "old-config-bundle.zip":
			if file.ExpectedClass == seedClassConfigOnly && strings.Contains(file.ExpectedPath, ".zip!") {
				foundConfigOnly = true
			}
		case "ssh-recovery.zip":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && strings.HasSuffix(file.ExpectedPath, "ssh-recovery.zip!keys/id_rsa") {
				foundPrivateKeyBundle = true
			}
		case "profile-backup.zip":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && strings.HasSuffix(file.ExpectedPath, "profile-backup.zip!Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234") {
				foundWinCredBundle = true
			}
		case "binary-media-bundle.zip":
			if file.IntendedAs == "filler/noise" {
				foundBinaryNoise = true
			}
		case "nested-export-bundle.zip":
			if file.IntendedAs == "filler/noise" {
				foundNestedNoise = true
			}
		case "oversized-config-export.zip":
			if file.IntendedAs == "filler/noise" && len(file.Content) > 10*1024*1024 {
				foundOversized = true
			}
		}
	}

	if !foundCorrelated {
		t.Fatal("expected zip seed pack to include correlated archive detection case")
	}
	if !foundActionable {
		t.Fatal("expected zip seed pack to include actionable archive detection case")
	}
	if !foundConfigOnly {
		t.Fatal("expected zip seed pack to include config-only archive case")
	}
	if !foundPrivateKeyBundle {
		t.Fatal("expected zip seed pack to include private key archive correlation case")
	}
	if !foundWinCredBundle {
		t.Fatal("expected zip seed pack to include windows credential-store archive correlation case")
	}
	if !foundBinaryNoise {
		t.Fatal("expected zip seed pack to include binary-only negative archive case")
	}
	if !foundNestedNoise {
		t.Fatal("expected zip seed pack to include nested-archive negative case")
	}
	if !foundOversized {
		t.Fatal("expected zip seed pack to include oversized archive case")
	}
}

func TestGenerateTARSeedPackIncludesPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260326,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundActionable := false
	foundCorrelated := false
	foundBinaryNoise := false
	foundNestedNoise := false
	foundOversized := false

	for _, file := range files {
		if file.Category != "tar-archives" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "linux-backup.tar":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "linux-backup.tar!etc/shadow.bak") {
				foundActionable = true
			}
		case "deploy-configs.tar.gz", "ops-recovery.tgz":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && strings.Contains(file.ExpectedPath, "!") {
				foundCorrelated = true
			}
		case "binary-drop.tar":
			if file.IntendedAs == "filler/noise" {
				foundBinaryNoise = true
			}
		case "nested-backup.tar.gz":
			if file.IntendedAs == "filler/noise" {
				foundNestedNoise = true
			}
		case "oversized-export.tgz":
			if file.IntendedAs == "filler/noise" && len(file.Content) > 10*1024*1024 {
				foundOversized = true
			}
		}
	}

	if !foundActionable || !foundCorrelated || !foundBinaryNoise || !foundNestedNoise || !foundOversized {
		t.Fatalf("expected tar seed pack to include positive and negative cases, got actionable=%v correlated=%v binary=%v nested=%v oversized=%v", foundActionable, foundCorrelated, foundBinaryNoise, foundNestedNoise, foundOversized)
	}
}

func TestGeneratedTARSeedProducesArchiveFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260326,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var tarSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "tar-archives" && file.ExpectedPath != "" && strings.EqualFold(file.Filename, "deploy-configs.tar.gz") {
			tarSeed = file
			break
		}
	}
	if tarSeed == nil {
		t.Fatal("expected generated tar archive seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: 128 * 1024 * 1024,
			MaxWIMSize:     128 * 1024 * 1024,
			MaxMembers:     8,
			MaxMemberBytes: 1024 * 1024,
			MaxTotalBytes:  4 * 1024 * 1024,
		},
	}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*tarSeed),
		Name:      tarSeed.Filename,
		Extension: ".gz",
		Size:      int64(len(tarSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, tarSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated tar seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == tarSeed.ExpectedPath && finding.ArchivePath == FullPath(*tarSeed) && finding.ArchiveMemberPath == "app/.env" {
			foundExpectedPath = true
			break
		}
	}
	if !foundExpectedPath {
		t.Fatalf("expected tar finding path %q, got %#v", tarSeed.ExpectedPath, evaluation.Findings)
	}
}

func TestGeneratedZIPSeedProducesArchiveFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var archiveSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && file.ExpectedPath != "" && strings.EqualFold(file.Filename, "deploy-package.zip") {
			archiveSeed = file
			break
		}
	}
	if archiveSeed == nil {
		t.Fatal("expected generated zip archive seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: 128 * 1024 * 1024,
			MaxWIMSize:     128 * 1024 * 1024,
			MaxMembers:     8,
			MaxMemberBytes: 1024 * 1024,
			MaxTotalBytes:  4 * 1024 * 1024,
		},
	}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*archiveSeed),
		Name:      archiveSeed.Filename,
		Extension: ".zip",
		Size:      int64(len(archiveSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, archiveSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated zip seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == archiveSeed.ExpectedPath && finding.ArchivePath == FullPath(*archiveSeed) && finding.ArchiveMemberPath == ".env" {
			foundExpectedPath = true
			break
		}
	}
	if !foundExpectedPath {
		t.Fatalf("expected archive finding path %q, got %#v", archiveSeed.ExpectedPath, evaluation.Findings)
	}
}

func TestGeneratedZIPSeedProducesPrivateKeyArchiveFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260323,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var archiveSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && file.ExpectedPath != "" && strings.EqualFold(file.Filename, "ssh-recovery.zip") {
			archiveSeed = file
			break
		}
	}
	if archiveSeed == nil {
		t.Fatal("expected generated private key zip archive seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: 128 * 1024 * 1024,
			MaxWIMSize:     128 * 1024 * 1024,
			MaxMembers:     8,
			MaxMemberBytes: 1024 * 1024,
			MaxTotalBytes:  4 * 1024 * 1024,
		},
	}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*archiveSeed),
		Name:      archiveSeed.Filename,
		Extension: ".zip",
		Size:      int64(len(archiveSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, archiveSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated private key zip seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	foundOVPN := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == archiveSeed.ExpectedPath && finding.ArchivePath == FullPath(*archiveSeed) && finding.ArchiveMemberPath == "keys/id_rsa" {
			foundExpectedPath = true
		}
		if finding.FilePath == FullPath(*archiveSeed)+"!vpn/client-admin.ovpn" {
			foundOVPN = true
		}
	}
	if !foundExpectedPath || !foundOVPN {
		t.Fatalf("expected private key and ovpn archive member findings, got %#v", evaluation.Findings)
	}
}

func TestGeneratedZIPSeedProducesWindowsCredentialStoreArchiveFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260324,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var archiveSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && file.ExpectedPath != "" && strings.EqualFold(file.Filename, "profile-backup.zip") {
			archiveSeed = file
			break
		}
	}
	if archiveSeed == nil {
		t.Fatal("expected generated windows credential-store zip archive seed")
	}

	engine := scanner.NewEngine(scanner.Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*archiveSeed),
		Name:      archiveSeed.Filename,
		Extension: ".zip",
		Size:      int64(len(archiveSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, archiveSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated windows credential-store zip seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	foundProtect := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == archiveSeed.ExpectedPath && finding.ArchivePath == FullPath(*archiveSeed) && finding.ArchiveMemberPath == "Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234" {
			foundExpectedPath = true
		}
		if strings.Contains(finding.FilePath, "Microsoft/Protect") {
			foundProtect = true
		}
	}
	if !foundExpectedPath || !foundProtect {
		t.Fatalf("expected windows credential-store archive member findings, got %#v", evaluation.Findings)
	}
}

func TestGeneratedOversizedZIPSeedIsSkippedByDefault(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260318,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var oversized *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "zip-archives" && strings.EqualFold(file.Filename, "oversized-config-export.zip") {
			oversized = file
			break
		}
	}
	if oversized == nil {
		t.Fatal("expected oversized zip seed")
	}

	engine := scanner.NewEngine(scanner.Options{}, &rules.Manager{}, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*oversized),
		Name:      oversized.Filename,
		Extension: ".zip",
		Size:      int64(len(oversized.Content)),
	}

	evaluation := engine.Evaluate(meta, oversized.Content)
	if !evaluation.Skipped || !strings.Contains(evaluation.SkipReason, "automatic inspection limit") {
		t.Fatalf("expected oversized zip seed to be skipped by default, got %#v", evaluation)
	}
}

func TestGenerateOfficeSeedPackIncludesPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 18,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundDOCX := false
	foundXLSX := false
	foundPPTX := false
	foundBenign := false

	for _, file := range files {
		if file.Category != "office-documents" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "credentials.docx":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "credentials.docx!word/document.xml") {
				foundDOCX = true
			}
		case "db-access.xlsx":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "db-access.xlsx!xl/sharedStrings.xml") {
				foundXLSX = true
			}
		case "vpn-rollout.pptx":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(file.ExpectedPath, "vpn-rollout.pptx!ppt/slides/slide1.xml") {
				foundPPTX = true
			}
		case "quarterly-update.docx", "inventory.xlsx", "townhall-notes.pptx":
			if file.IntendedAs == "filler/noise" && file.ExpectedPath == "" {
				foundBenign = true
			}
		}
	}

	if !foundDOCX || !foundXLSX || !foundPPTX || !foundBenign {
		t.Fatalf("expected office seed pack to include positive/negative cases, got docx=%v xlsx=%v pptx=%v benign=%v", foundDOCX, foundXLSX, foundPPTX, foundBenign)
	}
}

func TestGeneratedOfficeSeedProducesFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 18,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var officeSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "office-documents" && strings.EqualFold(file.Filename, "credentials.docx") {
			officeSeed = file
			break
		}
	}
	if officeSeed == nil {
		t.Fatal("expected generated office seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: 128 * 1024 * 1024,
			MaxWIMSize:     128 * 1024 * 1024,
			MaxMembers:     8,
			MaxMemberBytes: 1024 * 1024,
			MaxTotalBytes:  4 * 1024 * 1024,
		},
	}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*officeSeed),
		Name:      officeSeed.Filename,
		Extension: ".docx",
		Size:      int64(len(officeSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, officeSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated office seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	foundContentDriven := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == officeSeed.ExpectedPath && finding.ArchivePath == FullPath(*officeSeed) && finding.ArchiveMemberPath == "word/document.xml" {
			foundExpectedPath = true
		}
		if finding.FilePath == officeSeed.ExpectedPath && (finding.RuleID == "content.password_assignment_indicators" || finding.RuleID == "content.secret_assignment_indicators" || finding.RuleID == "content.database_connection_string_indicators" || finding.RuleID == "dbinspect.access.connection_string") {
			foundContentDriven = true
		}
	}
	if !foundExpectedPath {
		t.Fatalf("expected office finding path %q, got %#v", officeSeed.ExpectedPath, evaluation.Findings)
	}
	if !foundContentDriven {
		t.Fatalf("expected generated office seed to produce content-driven findings, got %#v", evaluation.Findings)
	}
}

func TestGeneratedOfficeSeedUsesNonPlaceholderCredentialShapes(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 18,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var officeSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "office-documents" && strings.EqualFold(file.Filename, "credentials.docx") {
			officeSeed = file
			break
		}
	}
	if officeSeed == nil {
		t.Fatal("expected generated office seed")
	}

	reader, err := zip.NewReader(bytes.NewReader(officeSeed.Content), int64(len(officeSeed.Content)))
	if err != nil {
		t.Fatalf("zip.NewReader returned error: %v", err)
	}

	var document string
	for _, file := range reader.File {
		if file.Name != "word/document.xml" {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("Open returned error: %v", err)
		}
		payload, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("ReadAll returned error: %v", err)
		}
		document = string(payload)
		break
	}
	if document == "" {
		t.Fatal("expected word/document.xml in generated office seed")
	}
	for _, want := range []string{"password=FAKE_DB_PASSWORD_", "client_secret=SAMPLE_CLIENT_SECRET_", "Server=db-"} {
		if !strings.Contains(document, want) {
			t.Fatalf("expected generated office seed to contain %q, got %q", want, document)
		}
	}
	for _, unwanted := range []string{"EXAMPLE_PASSWORD_", "DEMO_CONN_STRING_"} {
		if strings.Contains(document, unwanted) {
			t.Fatalf("expected generated office seed to avoid placeholder value %q, got %q", unwanted, document)
		}
	}
}

func TestGenerateWIMSeedPackIncludesPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("wimlib-imagex"); err != nil {
		t.Skip("wimlib-imagex not available")
	}

	files, err := Generate(GenerateOptions{
		CountPerCategory: 18,
		MaxFiles:         1200,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260330,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	foundCorrelated := false
	foundUnattend := false
	foundMDT := false
	foundBenign := false

	for _, file := range files {
		if file.Category != "wim-images" {
			continue
		}
		switch strings.ToLower(file.Filename) {
		case "domain-backup.wim":
			if file.ExpectedClass == seedClassCorrelatedHighConfidence && strings.HasSuffix(strings.ToLower(file.ExpectedPath), "domain-backup.wim!windows/ntds/ntds.dit") {
				foundCorrelated = true
			}
		case "deploy-image.wim":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(strings.ToLower(file.ExpectedPath), "deploy-image.wim!windows/panther/unattend.xml") {
				foundUnattend = true
			}
		case "mdt-capture.wim":
			if file.ExpectedClass == seedClassActionable && strings.HasSuffix(strings.ToLower(file.ExpectedPath), "mdt-capture.wim!deploy/control/bootstrap.ini") {
				foundMDT = true
			}
		case "reference-image.wim":
			if file.ExpectedClass == seedClassConfigOnly && file.ExpectedPath == "" {
				foundBenign = true
			}
		}
	}

	if !foundCorrelated || !foundUnattend || !foundMDT || !foundBenign {
		t.Fatalf("expected WIM seed pack to include positive/negative cases, got correlated=%v unattend=%v mdt=%v benign=%v", foundCorrelated, foundUnattend, foundMDT, foundBenign)
	}
}

func TestGeneratedWIMSeedProducesFindings(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("wimlib-imagex"); err != nil {
		t.Skip("wimlib-imagex not available")
	}

	files, err := Generate(GenerateOptions{
		CountPerCategory: 18,
		MaxFiles:         1200,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260330,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var wimSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "wim-images" && strings.EqualFold(file.Filename, "deploy-image.wim") {
			wimSeed = file
			break
		}
	}
	if wimSeed == nil {
		t.Fatal("expected generated WIM seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{
		WIM: wiminspect.Options{
			Enabled:        true,
			AutoWIMMaxSize: 128 * 1024 * 1024,
			MaxWIMSize:     128 * 1024 * 1024,
			MaxMembers:     8,
			MaxMemberBytes: 1024 * 1024,
			MaxTotalBytes:  4 * 1024 * 1024,
		},
	}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*wimSeed),
		Name:      wimSeed.Filename,
		Extension: ".wim",
		Size:      int64(len(wimSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, wimSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated WIM seed, got %#v", evaluation)
	}

	foundExpectedPath := false
	foundContentDriven := false
	for _, finding := range evaluation.Findings {
		if strings.EqualFold(finding.FilePath, wimSeed.ExpectedPath) &&
			strings.EqualFold(finding.ArchivePath, FullPath(*wimSeed)) &&
			strings.EqualFold(strings.ReplaceAll(finding.ArchiveMemberPath, `\`, "/"), "Windows/Panther/unattend.xml") {
			foundExpectedPath = true
		}
		if strings.EqualFold(finding.FilePath, wimSeed.ExpectedPath) &&
			(finding.RuleID == "content.unattended_deployment_password_fields" || finding.RuleID == "content.password_assignment_indicators") {
			foundContentDriven = true
		}
	}
	if !foundExpectedPath {
		t.Fatalf("expected WIM finding path %q, got %#v", wimSeed.ExpectedPath, evaluation.Findings)
	}
	if !foundContentDriven {
		t.Fatalf("expected generated WIM seed to produce content-driven findings, got %#v", evaluation.Findings)
	}
}

func TestGeneratedSQLiteSeedProducesFindings(t *testing.T) {
	t.Parallel()

	files, err := Generate(GenerateOptions{
		CountPerCategory: 24,
		MaxFiles:         900,
		SeedPrefix:       "SnablrLab",
		RandomSeed:       20260325,
	})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var sqliteSeed *SeedFile
	for i := range files {
		file := &files[i]
		if file.Category == "sqlite-databases" && strings.EqualFold(file.Filename, "customers-prod.sqlite") {
			sqliteSeed = file
			break
		}
	}
	if sqliteSeed == nil {
		t.Fatal("expected generated sqlite seed")
	}

	root := filepath.Join("..", "..", "configs", "rules", "default")
	manager, _, err := rules.LoadManager([]string{root}, false, rules.ManagerOptions{})
	if err != nil {
		t.Fatalf("LoadManager returned error: %v", err)
	}

	engine := scanner.NewEngine(scanner.Options{}, manager, nil, logx.New("error"))
	meta := scanner.FileMetadata{
		FilePath:  FullPath(*sqliteSeed),
		Name:      sqliteSeed.Filename,
		Extension: ".sqlite",
		Size:      int64(len(sqliteSeed.Content)),
	}
	evaluation := engine.Evaluate(meta, sqliteSeed.Content)
	if len(evaluation.Findings) == 0 {
		t.Fatalf("expected findings from generated sqlite seed, got %#v", evaluation)
	}

	foundSQLitePath := false
	for _, finding := range evaluation.Findings {
		if finding.FilePath == sqliteSeed.ExpectedPath && finding.DatabaseFilePath == FullPath(*sqliteSeed) {
			foundSQLitePath = true
			break
		}
	}
	if !foundSQLitePath {
		t.Fatalf("expected sqlite composite finding path %q, got %#v", sqliteSeed.ExpectedPath, evaluation.Findings)
	}
}
