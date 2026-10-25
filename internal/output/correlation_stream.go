package output

import (
	"context"
	"path/filepath"
	"strings"

	"snablr/internal/awsinspect"
	"snablr/internal/backupinspect"
	"snablr/internal/browsercredinspect"
	"snablr/internal/scanner"
	"snablr/internal/store"
	"snablr/internal/wincredinspect"
)

type correlationStreamKey struct{ host, share, context string }
type profileStreamKey struct{ host, share, profile string }
type correlationStreamPair struct{ left, right scanner.Finding }
type correlationStreamFamily struct{ first, second, third, fourth scanner.Finding }

type correlationStreamState struct {
	ad, aws, cert, sqlite     map[correlationStreamKey]correlationStreamPair
	private, browser, windows map[correlationStreamKey]correlationStreamFamily
	backup                    map[correlationStreamKey]*backupStreamBucket
}

type backupStreamBucket struct {
	artifacts map[string]scanner.Finding
	paths     map[string]scanner.Finding
}

func newCorrelationStreamState() *correlationStreamState {
	return &correlationStreamState{
		ad: make(map[correlationStreamKey]correlationStreamPair), cert: make(map[correlationStreamKey]correlationStreamPair), sqlite: make(map[correlationStreamKey]correlationStreamPair),
		aws: make(map[correlationStreamKey]correlationStreamPair), private: make(map[correlationStreamKey]correlationStreamFamily), browser: make(map[correlationStreamKey]correlationStreamFamily), windows: make(map[correlationStreamKey]correlationStreamFamily), backup: make(map[correlationStreamKey]*backupStreamBucket),
	}
}

func streamCorrelationKey(f scanner.Finding, context string) correlationStreamKey {
	return correlationStreamKey{host: strings.ToLower(strings.TrimSpace(f.Host)), share: strings.ToLower(strings.TrimSpace(f.Share)), context: strings.ToLower(strings.TrimSpace(context))}
}

func streamProfileKey(f scanner.Finding, profile string) correlationStreamKey {
	return correlationStreamKey{host: strings.ToLower(strings.TrimSpace(f.Host)), share: strings.ToLower(strings.TrimSpace(f.Share)), context: profile}
}

func streamBest(left, right scanner.Finding) scanner.Finding {
	if left.RuleID == "" {
		return right
	}
	return selectBestCorrelationAnchor([]scanner.Finding{left, right})
}

func streamPairAdd(m map[correlationStreamKey]correlationStreamPair, key correlationStreamKey, family string, f scanner.Finding) {
	if key.host == "" || key.share == "" || key.context == "" {
		return
	}
	p := m[key]
	switch family {
	case "left":
		p.left = streamBest(p.left, f)
	case "right":
		p.right = streamBest(p.right, f)
	}
	m[key] = p
}

func (s *correlationStreamState) add(f scanner.Finding) {
	if family := adArtifactFamily(f); family != "" {
		key := streamCorrelationKey(f, correlationDirectoryContext(f))
		if family == "ntds" {
			streamPairAdd(s.ad, key, "left", f)
		} else {
			streamPairAdd(s.ad, key, "right", f)
		}
	}
	if family := awsArtifactFamily(f); family != "" {
		key := streamProfileKey(f, awsinspect.ProfileContext(f.FilePath))
		if family == "credentials" {
			streamPairAdd(s.aws, key, "left", f)
		} else {
			streamPairAdd(s.aws, key, "right", f)
		}
	}
	if family := privateKeyArtifactFamily(f); family != "" {
		key := streamCorrelationKey(f, remoteAccessDirectoryContext(f))
		p := s.private[key]
		if family == "private-key" {
			p.first = streamBest(p.first, f)
		} else if family == "client-auth" {
			p.second = streamBest(p.second, f)
		} else {
			p.third = streamBest(p.third, f)
		}
		s.private[key] = p
	}
	if family := certificateBundleFamily(f); family != "" {
		key := streamCorrelationKey(f, remoteAccessDirectoryContext(f))
		if family == "certificate" {
			streamPairAdd(s.cert, key, "left", f)
		} else {
			streamPairAdd(s.cert, key, "right", f)
		}
	}
	if family := browserCredentialStoreFamily(f); family != "" {
		key := streamProfileKey(f, browsercredinspect.ProfileContext(f.FilePath))
		p := s.browser[key]
		switch family {
		case "firefox-logins":
			p.first = streamBest(p.first, f)
		case "firefox-key4":
			p.second = streamBest(p.second, f)
		case "chromium-login-data":
			p.third = streamBest(p.third, f)
		case "chromium-cookies":
			p.fourth = streamBest(p.fourth, f)
		}
		s.browser[key] = p
	}
	if family := windowsCredentialStoreFamily(f); family != "" {
		key := streamProfileKey(f, wincredinspect.ProfileContext(f.FilePath))
		p := s.windows[key]
		switch family {
		case "protect":
			p.first = streamBest(p.first, f)
		case "credentials":
			p.second = streamBest(p.second, f)
		case "vault":
			p.third = streamBest(p.third, f)
		}
		s.windows[key] = p
	}
	if family := sqliteCorrelationFamily(f); family != "" {
		key := streamCorrelationKey(f, filepath.Dir(sqliteBasePath(f)))
		p := s.sqlite[key]
		if family == "sqlite" {
			p.left = streamBest(p.left, f)
		} else {
			p.right = streamBest(p.right, f)
		}
		s.sqlite[key] = p
	}
	if context := backupinspect.BackupContext(f.FilePath); context != "" {
		key := streamCorrelationKey(f, context)
		b := s.backup[key]
		if b == nil {
			b = &backupStreamBucket{artifacts: make(map[string]scanner.Finding), paths: make(map[string]scanner.Finding)}
			s.backup[key] = b
		}
		if family := backupSecretArtifactFamily(f); family != "" {
			b.artifacts[family] = streamBest(b.artifacts[family], f)
		}
		if family := backupPathFamily(f); family != "" {
			b.paths[family] = streamBest(b.paths[family], f)
		}
	}
}

func persistStreamingCorrelations(ctx context.Context, shadow *store.SQLiteStore) error {
	state := newCorrelationStreamState()
	if err := shadow.IterateFindings(ctx, 256, func(batch []scanner.Finding) error {
		for _, f := range batch {
			state.add(f)
		}
		return nil
	}); err != nil {
		return err
	}
	persist := func(f scanner.Finding) error {
		if f.RuleID == "" {
			return nil
		}
		return shadow.RecordDerivedFinding(correlationFindingKey(f), f)
	}
	for _, p := range state.ad {
		if p.left.RuleID != "" && p.right.RuleID != "" {
			if err := persist(newADCorrelatedFinding(p.left, p.right)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.aws {
		if p.left.RuleID != "" && p.right.RuleID != "" {
			if err := persist(newAWSCorrelatedFinding(p.left, p.right)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.private {
		support, kind := p.second, "client-auth"
		if support.RuleID == "" {
			support, kind = p.third, "ssh-support"
		}
		if p.first.RuleID != "" && support.RuleID != "" {
			if err := persist(newPrivateKeyCorrelatedFinding(p.first, support, kind)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.cert {
		if p.left.RuleID != "" && p.right.RuleID != "" {
			if err := persist(newCertificateCorrelatedFinding(p.left, p.right)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.browser {
		if p.first.RuleID != "" && p.second.RuleID != "" {
			if err := persist(newBrowserCredentialStoreCorrelatedFinding(p.first, p.second, "Firefox logins.json + key4.db", "critical", 84)); err != nil {
				return err
			}
		}
		if p.third.RuleID != "" && p.fourth.RuleID != "" {
			if err := persist(newBrowserCredentialStoreCorrelatedFinding(p.third, p.fourth, "Chromium Login Data + Cookies", "high", 78)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.windows {
		if p.first.RuleID == "" {
			continue
		}
		support, match := p.second, "Protect + Credentials"
		if support.RuleID == "" {
			support, match = p.third, "Protect + Vault"
		}
		if p.second.RuleID != "" && p.third.RuleID != "" {
			support, match = streamBest(p.second, p.third), "Protect + Credentials + Vault"
		}
		if support.RuleID != "" {
			if err := persist(newWindowsCredentialStoreCorrelatedFinding(p.first, support, match)); err != nil {
				return err
			}
		}
	}
	for _, p := range state.sqlite {
		if p.left.RuleID != "" && p.right.RuleID != "" {
			if err := persist(newSQLiteCorrelatedFinding(p.left, p.right)); err != nil {
				return err
			}
		}
	}
	for _, b := range state.backup {
		if len(b.artifacts) < 2 {
			continue
		}
		primary := selectBestBackupPrimary(singletonFindingSlices(b.artifacts))
		support := selectBestBackupSupport(singletonFindingSlices(b.artifacts), primary)
		path := selectBestBackupPathSupport(singletonFindingSlices(b.paths))
		if err := persist(newBackupCorrelatedFinding(primary, support, path, describeBackupArtifactSet(singletonFindingSlices(b.artifacts), singletonFindingSlices(b.paths)))); err != nil {
			return err
		}
	}
	return shadow.Flush()
}

func singletonFindingSlices(values map[string]scanner.Finding) map[string][]scanner.Finding {
	out := make(map[string][]scanner.Finding, len(values))
	for key, value := range values {
		out[key] = []scanner.Finding{value}
	}
	return out
}
