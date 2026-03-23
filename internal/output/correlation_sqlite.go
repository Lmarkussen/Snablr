package output

import (
	"path/filepath"
	"strings"

	"snablr/internal/scanner"
)

const sqliteCorrelationRuleID = "correlation.database.sqlite_exposure"

func buildSQLiteCorrelatedFindings(findings []scanner.Finding) []scanner.Finding {
	type bucketKey struct {
		host  string
		share string
		dir   string
	}

	type bucket struct {
		sqlite  []scanner.Finding
		support []scanner.Finding
	}

	grouped := make(map[bucketKey]*bucket)
	for _, finding := range findings {
		family := sqliteCorrelationFamily(finding)
		if family == "" {
			continue
		}
		basePath := sqliteBasePath(finding)
		key := bucketKey{
			host:  strings.ToLower(strings.TrimSpace(finding.Host)),
			share: strings.ToLower(strings.TrimSpace(finding.Share)),
			dir:   strings.ToLower(strings.TrimSpace(filepath.ToSlash(filepath.Dir(basePath)))),
		}
		if key.host == "" || key.share == "" || key.dir == "" {
			continue
		}
		item := grouped[key]
		if item == nil {
			item = &bucket{}
			grouped[key] = item
		}
		if family == "sqlite" {
			item.sqlite = append(item.sqlite, finding)
			continue
		}
		item.support = append(item.support, finding)
	}

	out := make([]scanner.Finding, 0)
	for _, item := range grouped {
		if len(item.sqlite) == 0 || len(item.support) == 0 {
			continue
		}
		out = append(out, newSQLiteCorrelatedFinding(selectBestCorrelationAnchor(item.sqlite), selectBestCorrelationAnchor(item.support)))
	}
	return out
}

func sqliteCorrelationFamily(f scanner.Finding) string {
	if strings.TrimSpace(f.DatabaseFilePath) != "" && strings.TrimSpace(f.DatabaseTable) != "" && strings.TrimSpace(f.DatabaseColumn) != "" {
		return "sqlite"
	}

	base := strings.ToLower(strings.TrimSpace(filepath.Base(f.FilePath)))
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(base)))
	switch base {
	case ".env", "web.config", "appsettings.json", "database.yml", "application.properties", "config.php", "docker-compose.yml":
		return "support"
	}
	switch ext {
	case ".dsn", ".udl":
		return "support"
	case ".bak", ".dump", ".dmp":
		return "support"
	}
	switch strings.ToLower(strings.TrimSpace(f.Category)) {
	case "database-access", "database-infrastructure":
		return "support"
	default:
		return ""
	}
}

func sqliteBasePath(f scanner.Finding) string {
	path := strings.TrimSpace(f.DatabaseFilePath)
	if path == "" {
		path = strings.TrimSpace(f.FilePath)
	}
	if idx := strings.Index(path, "::"); idx >= 0 {
		path = path[:idx]
	}
	return path
}

func newSQLiteCorrelatedFinding(primary, support scanner.Finding) scanner.Finding {
	ruleIDs := append([]string{}, primary.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, support.MatchedRuleIDs...)
	ruleIDs = append(ruleIDs, sqliteCorrelationRuleID)

	context := "Paired artifact context:\n" + sqliteBasePath(primary) + "\n" + support.FilePath
	return scanner.Finding{
		RuleID:            sqliteCorrelationRuleID,
		RuleName:          "SQLite Exposure Path",
		Severity:          "high",
		Confidence:        "high",
		RuleConfidence:    "high",
		ConfidenceScore:   80,
		ConfidenceReasons: uniqueStrings([]string{"bounded SQLite row evidence was found near database or application configuration context", "nearby config or backup evidence increases the likelihood that the SQLite secret is operationally useful"}),
		Category:          "database-access",
		TriageClass:       "actionable",
		Actionable:        true,
		Correlated:        true,
		ConfidenceBreakdown: scanner.ConfidenceBreakdown{
			BaseScore:                   80,
			FinalScore:                  80,
			ContentSignalStrength:       18,
			HeuristicSignalContribution: 14,
			ValueQualityScore:           primary.ConfidenceBreakdown.ValueQualityScore,
			ValueQualityLabel:           firstNonEmpty(primary.ConfidenceBreakdown.ValueQualityLabel, "medium"),
			ValueQualityReason:          firstNonEmpty(primary.ConfidenceBreakdown.ValueQualityReason, "bounded SQLite inspection found a plausible secret or validated connection detail"),
			CorrelationContribution:     30,
			PathContextContribution:     10,
		},
		Priority:            maxInt(primary.Priority, support.Priority),
		PriorityReason:      firstNonEmpty(primary.PriorityReason, support.PriorityReason),
		SharePriority:       maxInt(primary.SharePriority, support.SharePriority),
		SharePriorityReason: firstNonEmpty(primary.SharePriorityReason, support.SharePriorityReason),
		FilePath:            primary.FilePath,
		Share:               primary.Share,
		ShareDescription:    primary.ShareDescription,
		ShareType:           primary.ShareType,
		Host:                primary.Host,
		Source:              firstNonEmpty(primary.Source, support.Source),
		ArchivePath:         firstNonEmpty(primary.ArchivePath, support.ArchivePath),
		ArchiveMemberPath:   firstNonEmpty(primary.ArchiveMemberPath, support.ArchiveMemberPath),
		ArchiveLocalInspect: primary.ArchiveLocalInspect || support.ArchiveLocalInspect,
		DatabaseFilePath:    primary.DatabaseFilePath,
		DatabaseTable:       primary.DatabaseTable,
		DatabaseColumn:      primary.DatabaseColumn,
		DatabaseRowContext:  primary.DatabaseRowContext,
		DFSNamespacePath:    firstNonEmpty(primary.DFSNamespacePath, support.DFSNamespacePath),
		DFSLinkPath:         firstNonEmpty(primary.DFSLinkPath, support.DFSLinkPath),
		SignalType:          "correlation",
		Match:               "sqlite secret + nearby config/backup context",
		MatchedText:         context,
		MatchedTextRedacted: context,
		Snippet:             "sqlite secret + nearby config/backup context",
		Context:             context,
		ContextRedacted:     context,
		MatchReason:         "cross-file correlation identified bounded SQLite credential evidence alongside nearby database or application configuration context.",
		RuleExplanation:     "This finding is promoted only when a SQLite row hit is reinforced by nearby database, application, or backup context in the same directory.",
		RuleRemediation:     "Remove embedded secrets from local SQLite stores, rotate exposed values, and review nearby application or backup material that makes the exposure operationally useful.",
		FromSYSVOL:          primary.FromSYSVOL || support.FromSYSVOL,
		FromNETLOGON:        primary.FromNETLOGON || support.FromNETLOGON,
		MatchedRuleIDs:      uniqueStrings(ruleIDs),
		MatchedSignalTypes:  []string{"correlation", "validated", "path"},
		SupportingSignals: []scanner.SupportingSignal{
			{
				SignalType: primary.SignalType,
				RuleID:     primary.RuleID,
				RuleName:   primary.RuleName,
				Match:      primary.Match,
				Confidence: primary.Confidence,
				Weight:     22,
				Reason:     "bounded SQLite inspection identified a validated connection detail or strong secret-like value",
			},
			{
				SignalType: support.SignalType,
				RuleID:     support.RuleID,
				RuleName:   support.RuleName,
				Match:      support.Match,
				Confidence: support.Confidence,
				Weight:     12,
				Reason:     "nearby application, database, or backup context reinforces the SQLite finding",
			},
			{
				SignalType: "correlation",
				RuleID:     sqliteCorrelationRuleID,
				RuleName:   "SQLite Exposure Path",
				Match:      "sqlite secret + nearby config/backup context",
				Confidence: "high",
				Weight:     30,
				Reason:     "paired SQLite and nearby config evidence suggest a usable access path rather than an isolated local artifact",
			},
		},
		Tags: uniqueStrings(append(append([]string{}, primary.Tags...), "correlation:sqlite-exposure-path", "artifact:sqlite")),
	}
}
