package output

import (
	"path/filepath"
	"regexp"
	"strings"

	"snablr/internal/scanner"
)

const privateKeyCorrelationRuleID = "correlation.remote_access.private_key_bundle"
const certificateBundleCorrelationRuleID = "correlation.remote_access.certificate_bundle"

var syntheticTierDirPattern = regexp.MustCompile(`(?i)^tier-\d+$`)

func buildPrivateKeyCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host  string
		share string
		dir   string
	}

	type pairBucket struct {
		privateKeys []scanner.Finding
		clientAuth  []scanner.Finding
		sshSupport  []scanner.Finding
	}

	grouped := make(map[bucketKey]*pairBucket)
	for _, finding := range findings {
		family := privateKeyArtifactFamily(finding)
		if family == "" {
			continue
		}
		key := bucketKey{
			host:  strings.ToLower(strings.TrimSpace(finding.Host)),
			share: strings.ToLower(strings.TrimSpace(finding.Share)),
			dir:   strings.ToLower(strings.TrimSpace(remoteAccessDirectoryContext(finding))),
		}
		if key.host == "" || key.share == "" || key.dir == "" {
			continue
		}
		bucket := grouped[key]
		if bucket == nil {
			bucket = &pairBucket{}
			grouped[key] = bucket
		}
		switch family {
		case "private-key":
			bucket.privateKeys = append(bucket.privateKeys, finding)
		case "client-auth":
			bucket.clientAuth = append(bucket.clientAuth, finding)
		case "ssh-support":
			bucket.sshSupport = append(bucket.sshSupport, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		if len(bucket.privateKeys) == 0 {
			continue
		}
		var support scanner.Finding
		supportKind := ""
		switch {
		case len(bucket.clientAuth) > 0:
			support = selectBestCorrelationAnchor(bucket.clientAuth)
			supportKind = "client-auth"
		case len(bucket.sshSupport) > 0:
			support = selectBestCorrelationAnchor(bucket.sshSupport)
			supportKind = "ssh-support"
		default:
			continue
		}
		out = append(out, newPrivateKeyCorrelatedFinding(selectBestCorrelationAnchor(bucket.privateKeys), support, supportKind))
	}
	return out
}

func buildCertificateCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host  string
		share string
		dir   string
	}

	type pairBucket struct {
		certificates []scanner.Finding
		passwords    []scanner.Finding
	}

	grouped := make(map[bucketKey]*pairBucket)
	for _, finding := range findings {
		family := certificateBundleFamily(finding)
		if family == "" {
			continue
		}
		key := bucketKey{
			host:  strings.ToLower(strings.TrimSpace(finding.Host)),
			share: strings.ToLower(strings.TrimSpace(finding.Share)),
			dir:   strings.ToLower(strings.TrimSpace(remoteAccessDirectoryContext(finding))),
		}
		if key.host == "" || key.share == "" || key.dir == "" {
			continue
		}
		bucket := grouped[key]
		if bucket == nil {
			bucket = &pairBucket{}
			grouped[key] = bucket
		}
		switch family {
		case "certificate":
			bucket.certificates = append(bucket.certificates, finding)
		case "password-evidence":
			bucket.passwords = append(bucket.passwords, finding)
		}
	}

	out := make([]scanner.Finding, 0, len(grouped))
	for _, bucket := range grouped {
		if len(bucket.certificates) == 0 || len(bucket.passwords) == 0 {
			continue
		}
		out = append(out, newCertificateCorrelatedFinding(
			selectBestCorrelationAnchor(bucket.certificates),
			selectBestCorrelationAnchor(bucket.passwords),
		))
	}
	return out
}

func privateKeyArtifactFamily(f scanner.Finding) string {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(f.FilePath)))
	switch {
	case base == "id_rsa" || base == "id_ed25519" || base == "id_ecdsa" || base == "id_dsa" || base == "identity":
		return "private-key"
	case base == "authorized_keys" || base == "known_hosts":
		return "ssh-support"
	case base == ".ovpn" || base == ".ppk":
		return "client-auth"
	}

	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(base)))
	switch ext {
	case ".ovpn", ".ppk":
		return "client-auth"
	}

	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "keyinspect.content.private_key_header", "filename.private_key_artifacts":
		return "private-key"
	case "filename.ssh_supporting_artifacts":
		return "ssh-support"
	case "extension.client_auth_artifacts":
		return "client-auth"
	default:
		return ""
	}
}

func certificateBundleFamily(f scanner.Finding) string {
	base := strings.ToLower(strings.TrimSpace(filepath.Base(f.FilePath)))
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(base)))
	switch ext {
	case ".pfx", ".p12":
		if strings.EqualFold(strings.TrimSpace(f.RuleID), "extension.key_and_certificate_extensions") {
			return "certificate"
		}
	}

	switch strings.ToLower(strings.TrimSpace(f.RuleID)) {
	case "content.password_assignment_indicators", "content.password_note_value_indicators", "content.note_style_credential_pair_indicators":
		return "password-evidence"
	default:
		return ""
	}
}

func remoteAccessDirectoryContext(f scanner.Finding) string {
	if strings.TrimSpace(f.ArchivePath) != "" {
		memberDir := strings.TrimSpace(filepath.ToSlash(filepath.Dir(f.ArchiveMemberPath)))
		if memberDir != "." && memberDir != "" {
			return strings.TrimSpace(filepath.ToSlash(f.ArchivePath)) + "!" + collapseSyntheticTierDir(memberDir)
		}
		return strings.TrimSpace(filepath.ToSlash(f.ArchivePath))
	}
	return collapseSyntheticTierDir(strings.TrimSpace(filepath.ToSlash(filepath.Dir(f.FilePath))))
}

func collapseSyntheticTierDir(value string) string {
	value = strings.TrimSpace(filepath.ToSlash(value))
	if value == "" || value == "." {
		return value
	}
	base := strings.TrimSpace(filepath.Base(value))
	if syntheticTierDirPattern.MatchString(base) {
		parent := strings.TrimSpace(filepath.ToSlash(filepath.Dir(value)))
		if parent != "" && parent != "." {
			return parent
		}
	}
	return value
}

func newPrivateKeyCorrelatedFinding(privateKey, support scanner.Finding, supportKind string) scanner.Finding {
	ruleIDs := append([]string{}, privateKey.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, support.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, privateKeyCorrelationRuleID)

	supportLabel := "SSH supporting context"
	supportReason := "nearby SSH support artifacts increase the likelihood that the exposed private key is operationally useful"
	matchText := "private key + SSH support"
	severity := "high"
	score := 76
	pathContribution := 10
	correlationContribution := 28
	tags := []string{"correlation:remote-access-bundle", "artifact:private-key"}
	if supportKind == "client-auth" {
		supportLabel = "Client-auth artifact context"
		supportReason = "nearby client-auth artifacts increase the likelihood that the exposed private key is part of a reusable access bundle"
		matchText = "private key + client-auth artifact"
		severity = "critical"
		score = 84
		pathContribution = 12
		correlationContribution = 34
		tags = append(tags, "artifact:client-auth")
	} else {
		tags = append(tags, "artifact:ssh-support")
	}

	reasons := uniqueStrings([]string{
		"private key material and related access artifacts were found together in the same directory context",
		supportReason,
	})

	signals := []scanner.SupportingSignal{
		{
			SignalType: privateKey.SignalType,
			RuleID:     privateKey.RuleID,
			RuleName:   privateKey.RuleName,
			Match:      filepath.Base(privateKey.FilePath),
			Confidence: privateKey.Confidence,
			Weight:     22,
			Reason:     "exact private key artifact or validated private key header was identified",
		},
		{
			SignalType: support.SignalType,
			RuleID:     support.RuleID,
			RuleName:   support.RuleName,
			Match:      filepath.Base(support.FilePath),
			Confidence: support.Confidence,
			Weight:     14,
			Reason:     supportLabel,
		},
		{
			SignalType: "path",
			Weight:     pathContribution,
			Reason:     "private key and related artifact were found in the same host/share/directory context",
		},
		{
			SignalType: "correlation",
			RuleID:     privateKeyCorrelationRuleID,
			RuleName:   "Private Key Exposure Path",
			Match:      matchText,
			Confidence: "high",
			Weight:     correlationContribution,
			Reason:     supportReason,
		},
	}

	allTags := uniqueStrings(append(append(append([]string{}, privateKey.Tags...), support.Tags...), tags...))
	context := "Paired artifact context:\n" + privateKey.FilePath + "\n" + support.FilePath
	return scanner.Finding{
		RuleID:            privateKeyCorrelationRuleID,
		RuleName:          "Private Key Exposure Path",
		Severity:          severity,
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   score,
		ConfidenceReasons: reasons,
		Category:          "remote-access",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   score,
			FinalScore:                  score,
			ContentSignalStrength:       0,
			HeuristicSignalContribution: 36,
			ValueQualityScore:           0,
			ValueQualityLabel:           "medium",
			ValueQualityReason:          "confidence comes from exact artifact identity, validated private key structure, and nearby client-auth or SSH context",
			CorrelationContribution:     correlationContribution,
			PathContextContribution:     pathContribution,
		},
		Priority:            maxInt(privateKey.Priority, support.Priority),
		PriorityReason:      firstNonEmpty(privateKey.PriorityReason, support.PriorityReason),
		SharePriority:       maxInt(privateKey.SharePriority, support.SharePriority),
		SharePriorityReason: firstNonEmpty(privateKey.SharePriorityReason, support.SharePriorityReason),
		FilePath:            privateKey.FilePath,
		Share:               privateKey.Share,
		ShareDescription:    privateKey.ShareDescription,
		ShareType:           privateKey.ShareType,
		Host:                privateKey.Host,
		Source:              firstNonEmpty(privateKey.Source, support.Source),
		ArchivePath:         firstNonEmpty(privateKey.ArchivePath, support.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(privateKey.ArchiveMemberPath, support.ArchiveMemberPath),
		ArchiveLocalInspect: privateKey.ArchiveLocalInspect || support.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(privateKey.DFSNamespacePath, support.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(privateKey.DFSLinkPath, support.DFSLinkPath),
		SignalType:          "correlation",
		Match:               matchText,
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             matchText,
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified exposed private key material alongside nearby client-auth or SSH support artifacts.",
		RuleExplanation:     "This finding is promoted only when an exposed private key artifact appears with nearby client-auth or SSH support files in the same directory context.",
		RuleRemediation:     "Restrict access immediately, remove unnecessary key material and related client-auth artifacts from shared storage, and rotate or replace exposed keys and access profiles.",
		FromSYSVOL:          privateKey.FromSYSVOL || support.FromSYSVOL,
		FromNETLOGON:        privateKey.FromNETLOGON || support.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "filename", "path"},
		SupportingSignals:   signals,
		Tags:                allTags,
	}
}

func newCertificateCorrelatedFinding(certificate, passwordEvidence scanner.Finding) scanner.Finding {
	ruleIDs := append([]string{}, certificate.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, passwordEvidence.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, certificateBundleCorrelationRuleID)

	reasons := uniqueStrings([]string{
		"PKCS#12 certificate material and nearby password evidence were found together in the same directory context",
		"paired certificate bundle and password note increase the chance that reusable client-auth material is exposed",
	})

	signals := []scanner.SupportingSignal{
		{
			SignalType: certificate.SignalType,
			RuleID:     certificate.RuleID,
			RuleName:   certificate.RuleName,
			Match:      filepath.Base(certificate.FilePath),
			Confidence: certificate.Confidence,
			Weight:     20,
			Reason:     "exact PKCS#12 certificate bundle artifact was identified",
		},
		{
			SignalType: passwordEvidence.SignalType,
			RuleID:     passwordEvidence.RuleID,
			RuleName:   passwordEvidence.RuleName,
			Match:      passwordEvidence.Match,
			Confidence: passwordEvidence.Confidence,
			Weight:     18,
			Reason:     "nearby password or credential note provides likely import password context for the certificate bundle",
		},
		{
			SignalType: "path",
			Weight:     12,
			Reason:     "certificate bundle and password evidence were found in the same host/share/directory context",
		},
		{
			SignalType: "correlation",
			RuleID:     certificateBundleCorrelationRuleID,
			RuleName:   "Certificate Access Bundle",
			Match:      "PKCS#12 bundle + password evidence",
			Confidence: "high",
			Weight:     32,
			Reason:     "paired PKCS#12 material and password evidence strongly suggest reusable client-auth access material",
		},
	}

	tags := uniqueStrings(append(append([]string{}, certificate.Tags...), passwordEvidence.Tags...))
	tags = append(tags, "correlation:certificate-access-bundle", "artifact:pkcs12", "artifact:password-evidence", "artifact:client-auth")
	context := "Paired artifact context:\n" + certificate.FilePath + "\n" + passwordEvidence.FilePath
	return scanner.Finding{
		RuleID:            certificateBundleCorrelationRuleID,
		RuleName:          "Certificate Access Bundle",
		Severity:          "critical",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   82,
		ConfidenceReasons: reasons,
		Category:          "remote-access",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   82,
			FinalScore:                  82,
			ContentSignalStrength:       18,
			HeuristicSignalContribution: 20,
			ValueQualityScore:           0,
			ValueQualityLabel:           "medium",
			ValueQualityReason:          "confidence comes from exact PKCS#12 artifact identity plus nearby password evidence",
			CorrelationContribution:     32,
			PathContextContribution:     12,
		},
		Priority:            maxInt(certificate.Priority, passwordEvidence.Priority),
		PriorityReason:      firstNonEmpty(certificate.PriorityReason, passwordEvidence.PriorityReason),
		SharePriority:       maxInt(certificate.SharePriority, passwordEvidence.SharePriority),
		SharePriorityReason: firstNonEmpty(certificate.SharePriorityReason, passwordEvidence.SharePriorityReason),
		FilePath:            certificate.FilePath,
		Share:               certificate.Share,
		ShareDescription:    certificate.ShareDescription,
		ShareType:           certificate.ShareType,
		Host:                certificate.Host,
		Source:              firstNonEmpty(certificate.Source, passwordEvidence.Source),
		ArchivePath:         firstNonEmpty(certificate.ArchivePath, passwordEvidence.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(certificate.ArchiveMemberPath, passwordEvidence.ArchiveMemberPath),
		ArchiveLocalInspect: certificate.ArchiveLocalInspect || passwordEvidence.ArchiveLocalInspect,
		DFSNamespacePath:    firstNonEmpty(certificate.DFSNamespacePath, passwordEvidence.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(certificate.DFSLinkPath, passwordEvidence.DFSLinkPath),
		SignalType:          "correlation",
		Match:               "PKCS#12 bundle + password evidence",
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             "PKCS#12 bundle + password evidence",
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified PKCS#12 certificate material alongside nearby password evidence.",
		RuleExplanation:     "This finding is promoted only when a `.pfx` or `.p12` artifact appears with nearby password-oriented evidence in the same directory context.",
		RuleRemediation:     "Restrict access immediately, remove unnecessary PKCS#12 bundles and nearby password notes from shared storage, and rotate or replace exposed client certificates and passwords.",
		FromSYSVOL:          certificate.FromSYSVOL || passwordEvidence.FromSYSVOL,
		FromNETLOGON:        certificate.FromNETLOGON || passwordEvidence.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "content", "extension", "path"},
		SupportingSignals:   signals,
		Tags:                tags,
	}
}
