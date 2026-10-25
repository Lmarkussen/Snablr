package output

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"snablr/internal/awsinspect"
	"snablr/internal/backupinspect"
	"snablr/internal/browsercredinspect"
	"snablr/internal/scanner"
	"snablr/internal/store"
	"snablr/internal/wincredinspect"
)

func diskCorrelationGroup(f scanner.Finding, context string) string {
	return strings.Join([]string{strings.ToLower(strings.TrimSpace(f.Host)), strings.ToLower(strings.TrimSpace(f.Share)), strings.ToLower(strings.TrimSpace(context))}, "\x00")
}

func recordDiskCorrelationCandidate(s *store.SQLiteStore, family, group, slot string, f scanner.Finding) error {
	if group == "\x00\x00" || strings.TrimSpace(slot) == "" {
		return nil
	}
	return s.RecordCorrelationState(family, group, slot, f.ConfidenceScore, severityRank(f.Severity), f.FilePath, f)
}

// persistDiskBackedCorrelations spills every candidate to indexed SQLite state,
// then walks one group at a time. No Go collection grows with finding count or
// distinct relationship groups; one family/group's selected anchors are the
// maximum live correlation payload.
func persistDiskBackedCorrelations(ctx context.Context, shadow *store.SQLiteStore) error {
	if err := shadow.ResetCorrelationState(); err != nil {
		return fmt.Errorf("reset correlation state: %w", err)
	}
	if err := shadow.Flush(); err != nil {
		return fmt.Errorf("flush correlation reset: %w", err)
	}
	if err := shadow.IterateFindings(ctx, 256, func(batch []scanner.Finding) error {
		for _, f := range batch {
			if err := recordDiskCandidate(shadow, f); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := shadow.Flush(); err != nil {
		return fmt.Errorf("flush correlation candidates: %w", err)
	}
	if err := shadow.ForEachCorrelationGroup(ctx, func(family, group string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		get := func(slot string) (scanner.Finding, bool, error) {
			return shadow.BestCorrelationState(ctx, family, group, slot)
		}
		persist := func(f scanner.Finding) error {
			if f.RuleID == "" {
				return nil
			}
			return shadow.RecordDerivedFinding(correlationFindingKey(f), f)
		}
		switch family {
		case "ad":
			left, lok, err := get("ntds")
			if err != nil {
				return err
			}
			right, rok, err := get("system")
			if err != nil {
				return err
			}
			if lok && rok {
				return persist(newADCorrelatedFinding(left, right))
			}
		case "aws":
			left, lok, err := get("credentials")
			if err != nil {
				return err
			}
			right, rok, err := get("config")
			if err != nil {
				return err
			}
			if lok && rok {
				return persist(newAWSCorrelatedFinding(left, right))
			}
		case "private":
			left, lok, err := get("private-key")
			if err != nil {
				return err
			}
			support, ok, err := get("client-auth")
			if err != nil {
				return err
			}
			kind := "client-auth"
			if !ok {
				support, ok, err = get("ssh-support")
				if err != nil {
					return err
				}
				kind = "ssh-support"
			}
			if lok && ok {
				return persist(newPrivateKeyCorrelatedFinding(left, support, kind))
			}
		case "certificate":
			left, lok, err := get("certificate")
			if err != nil {
				return err
			}
			right, rok, err := get("password-evidence")
			if err != nil {
				return err
			}
			if lok && rok {
				return persist(newCertificateCorrelatedFinding(left, right))
			}
		case "browser":
			left, lok, err := get("firefox-logins")
			if err != nil {
				return err
			}
			right, rok, err := get("firefox-key4")
			if err != nil {
				return err
			}
			if lok && rok {
				if err := persist(newBrowserCredentialStoreCorrelatedFinding(left, right, "Firefox logins.json + key4.db", "critical", 84)); err != nil {
					return err
				}
			}
			left, lok, err = get("chromium-login-data")
			if err != nil {
				return err
			}
			right, rok, err = get("chromium-cookies")
			if err != nil {
				return err
			}
			if lok && rok {
				return persist(newBrowserCredentialStoreCorrelatedFinding(left, right, "Chromium Login Data + Cookies", "high", 78))
			}
		case "windows":
			protect, pok, err := get("protect")
			if err != nil {
				return err
			}
			credentials, cok, err := get("credentials")
			if err != nil {
				return err
			}
			vault, vok, err := get("vault")
			if err != nil {
				return err
			}
			if pok && (cok || vok) {
				support, match := credentials, "Protect + Credentials"
				if cok && vok {
					support, match = selectBestCorrelationAnchor([]scanner.Finding{credentials, vault}), "Protect + Credentials + Vault"
				} else if !cok {
					support, match = vault, "Protect + Vault"
				}
				return persist(newWindowsCredentialStoreCorrelatedFinding(protect, support, match))
			}
		case "sqlite":
			left, lok, err := get("sqlite")
			if err != nil {
				return err
			}
			right, rok, err := get("support")
			if err != nil {
				return err
			}
			if lok && rok {
				return persist(newSQLiteCorrelatedFinding(left, right))
			}
		case "backup":
			artifacts := make(map[string]scanner.Finding)
			for _, name := range []string{"ntds", "system", "sam", "security"} {
				if f, ok, err := get("artifact:" + name); err != nil {
					return err
				} else if ok {
					artifacts[name] = f
				}
			}
			if len(artifacts) < 2 {
				return nil
			}
			paths := make(map[string]scanner.Finding)
			for _, name := range []string{"windowsimagebackup", "system-volume-information", "regback", "windows-repair"} {
				if f, ok, err := get("path:" + name); err != nil {
					return err
				} else if ok {
					paths[name] = f
				}
			}
			primary := selectBestBackupPrimary(singletonFindingSlices(artifacts))
			support := selectBestBackupSupport(singletonFindingSlices(artifacts), primary)
			path := selectBestBackupPathSupport(singletonFindingSlices(paths))
			return persist(newBackupCorrelatedFinding(primary, support, path, describeBackupArtifactSet(singletonFindingSlices(artifacts), singletonFindingSlices(paths))))
		}
		return nil
	}); err != nil {
		return fmt.Errorf("walk correlation groups: %w", err)
	}
	if err := shadow.Flush(); err != nil {
		return fmt.Errorf("flush derived findings: %w", err)
	}
	if err := shadow.CompleteCorrelationState(); err != nil {
		return fmt.Errorf("publish correlation state: %w", err)
	}
	if err := shadow.Flush(); err != nil {
		return fmt.Errorf("flush published correlation state: %w", err)
	}
	return nil
}

func recordDiskCandidate(s *store.SQLiteStore, f scanner.Finding) error {
	if family := adArtifactFamily(f); family != "" {
		if err := recordDiskCorrelationCandidate(s, "ad", diskCorrelationGroup(f, correlationDirectoryContext(f)), family, f); err != nil {
			return err
		}
	}
	if family := awsArtifactFamily(f); family != "" {
		if profile := awsinspect.ProfileContext(f.FilePath); profile != "" {
			if err := recordDiskCorrelationCandidate(s, "aws", diskCorrelationGroup(f, profile), family, f); err != nil {
				return err
			}
		}
	}
	if family := privateKeyArtifactFamily(f); family != "" {
		if err := recordDiskCorrelationCandidate(s, "private", diskCorrelationGroup(f, remoteAccessDirectoryContext(f)), family, f); err != nil {
			return err
		}
	}
	if family := certificateBundleFamily(f); family != "" {
		if err := recordDiskCorrelationCandidate(s, "certificate", diskCorrelationGroup(f, remoteAccessDirectoryContext(f)), family, f); err != nil {
			return err
		}
	}
	if family := browserCredentialStoreFamily(f); family != "" {
		if profile := browsercredinspect.ProfileContext(f.FilePath); profile != "" {
			if err := recordDiskCorrelationCandidate(s, "browser", diskCorrelationGroup(f, profile), family, f); err != nil {
				return err
			}
		}
	}
	if family := windowsCredentialStoreFamily(f); family != "" {
		if profile := wincredinspect.ProfileContext(f.FilePath); profile != "" {
			if err := recordDiskCorrelationCandidate(s, "windows", diskCorrelationGroup(f, profile), family, f); err != nil {
				return err
			}
		}
	}
	if family := sqliteCorrelationFamily(f); family != "" {
		if err := recordDiskCorrelationCandidate(s, "sqlite", diskCorrelationGroup(f, filepath.Dir(sqliteBasePath(f))), family, f); err != nil {
			return err
		}
	}
	if context := backupinspect.BackupContext(f.FilePath); context != "" {
		group := diskCorrelationGroup(f, context)
		if family := backupSecretArtifactFamily(f); family != "" {
			if err := recordDiskCorrelationCandidate(s, "backup", group, "artifact:"+family, f); err != nil {
				return err
			}
		}
		if family := backupPathFamily(f); family != "" {
			if err := recordDiskCorrelationCandidate(s, "backup", group, "path:"+family, f); err != nil {
				return err
			}
		}
	}
	return nil
}
