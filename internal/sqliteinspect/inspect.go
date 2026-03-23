package sqliteinspect

import (
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"snablr/internal/dbinspect"
)

type tableSchema struct {
	Name    string
	Columns []string
	Score   int
}

func (i Inspector) NeedsContent(candidate Candidate) bool {
	shouldInspect, _ := ShouldInspect(candidate, i.opts)
	return shouldInspect
}

func (i Inspector) InspectContent(candidate Candidate, content []byte) []Match {
	shouldInspect, _ := ShouldInspect(candidate, i.opts)
	if !shouldInspect || len(content) == 0 || !hasSQLiteHeader(content) {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "snablr-sqlite-*.db")
	if err != nil {
		return nil
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if _, err := tmpFile.Write(content); err != nil {
		_ = tmpFile.Close()
		return nil
	}
	if err := tmpFile.Close(); err != nil {
		return nil
	}

	db, err := sql.Open("sqlite3", fmt.Sprintf("file:%s?mode=ro&_query_only=1", tmpPath))
	if err != nil {
		return nil
	}
	defer db.Close()

	tables, err := interestingTables(db, i.opts.MaxTables)
	if err != nil || len(tables) == 0 {
		return nil
	}

	matches := make([]Match, 0)
	seen := make(map[string]struct{})
	totalBytes := int64(0)
	for _, table := range tables {
		interestingColumns, contextColumns := splitInterestingColumns(table.Columns, i.opts.MaxInterestingCols)
		if len(interestingColumns) == 0 {
			continue
		}
		tableMatches, consumed := i.inspectTable(db, candidate, table.Name, interestingColumns, contextColumns)
		totalBytes += consumed
		for _, match := range tableMatches {
			key := strings.ToLower(match.ID + "::" + match.DatabaseTable + "::" + match.DatabaseColumn + "::" + match.Match)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matches = append(matches, match)
		}
		if i.opts.MaxTotalBytes > 0 && totalBytes >= i.opts.MaxTotalBytes {
			break
		}
	}

	return matches
}

func interestingTables(db *sql.DB, limit int) ([]tableSchema, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tables := make([]tableSchema, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}
		score := tablePriority(name)
		if score <= 0 {
			continue
		}
		columns, err := tableColumns(db, name)
		if err != nil || len(columns) == 0 {
			continue
		}
		tables = append(tables, tableSchema{Name: name, Columns: columns, Score: score})
	}
	sort.Slice(tables, func(i, j int) bool {
		if tables[i].Score == tables[j].Score {
			return strings.ToLower(tables[i].Name) < strings.ToLower(tables[j].Name)
		}
		return tables[i].Score > tables[j].Score
	})
	if limit > 0 && len(tables) > limit {
		tables = tables[:limit]
	}
	return tables, nil
}

func tableColumns(db *sql.DB, table string) ([]string, error) {
	rows, err := db.Query(`PRAGMA table_info(` + quoteIdent(table) + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	columns := make([]string, 0)
	for rows.Next() {
		var (
			cid       int
			name      string
			typ       string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		columns = append(columns, name)
	}
	return columns, nil
}

func splitInterestingColumns(columns []string, maxInteresting int) ([]string, []string) {
	prioritized := make([]namedScore, 0)
	context := make([]string, 0, 2)
	for _, column := range columns {
		if score := columnPriority(column); score > 0 {
			prioritized = append(prioritized, namedScore{Name: column, Score: score})
			continue
		}
		if len(context) < 2 && isContextColumn(column) {
			context = append(context, column)
		}
	}
	sortNamedScores(prioritized)
	if maxInteresting > 0 && len(prioritized) > maxInteresting {
		prioritized = prioritized[:maxInteresting]
	}

	interesting := make([]string, 0, len(prioritized))
	for _, item := range prioritized {
		interesting = append(interesting, item.Name)
	}
	return interesting, context
}

func (i Inspector) inspectTable(db *sql.DB, candidate Candidate, table string, interestingColumns, contextColumns []string) ([]Match, int64) {
	selectColumns := append([]string{}, interestingColumns...)
	selectColumns = append(selectColumns, contextColumns...)
	quoted := make([]string, 0, len(selectColumns))
	for _, column := range selectColumns {
		quoted = append(quoted, quoteIdent(column))
	}

	query := fmt.Sprintf(`SELECT %s FROM %s LIMIT %d`, strings.Join(quoted, ", "), quoteIdent(table), maxInt(i.opts.MaxRowsPerTable, 1))
	rows, err := db.Query(query)
	if err != nil {
		return nil, 0
	}
	defer rows.Close()

	interestingSet := make(map[string]struct{}, len(interestingColumns))
	for _, column := range interestingColumns {
		interestingSet[column] = struct{}{}
	}
	contextSet := make(map[string]struct{}, len(contextColumns))
	for _, column := range contextColumns {
		contextSet[column] = struct{}{}
	}

	totalBytes := int64(0)
	out := make([]Match, 0)
	for rows.Next() {
		values := make([]any, len(selectColumns))
		scanTargets := make([]any, len(selectColumns))
		for idx := range scanTargets {
			scanTargets[idx] = &values[idx]
		}
		if err := rows.Scan(scanTargets...); err != nil {
			continue
		}

		contextSummary := buildRowContext(selectColumns, values, contextSet, i.opts.MaxCellBytes)
		for idx, column := range selectColumns {
			if _, ok := interestingSet[column]; !ok {
				continue
			}
			cellValue, consumed, ok := normalizeCellValue(values[idx], i.opts.MaxCellBytes)
			if !ok {
				continue
			}
			totalBytes += consumed
			if i.opts.MaxTotalBytes > 0 && totalBytes > i.opts.MaxTotalBytes {
				return out, totalBytes
			}

			out = append(out, i.matchForCell(candidate, table, column, cellValue, contextSummary)...)
		}
	}
	return out, totalBytes
}

func (i Inspector) matchForCell(candidate Candidate, table, column, value, rowContext string) []Match {
	filePath := baseFilePath(candidate.FilePath)
	quality := assessSensitiveValueQuality(value)
	columnName := strings.ToLower(strings.TrimSpace(column))
	if strings.Contains(columnName, "connection") || strings.Contains(columnName, "dsn") || strings.Contains(columnName, "db_url") || strings.Contains(columnName, "database_url") {
		dbMatches := dbinspect.New().InspectContent(dbinspect.Candidate{
			FilePath:  filePath,
			Name:      fileBase(filePath),
			Extension: normalizedExtension(candidate.Extension),
			Size:      candidate.Size,
		}, []byte(value))
		out := make([]Match, 0, len(dbMatches))
		for _, dbMatch := range dbMatches {
			out = append(out, Match{
				ID:                  "sqliteinspect.access.connection_string",
				Name:                "SQLite-Stored Database Access Detail",
				Description:         "A SQLite column contained a validated database connection string or DSN.",
				RuleType:            "content",
				SignalType:          "validated",
				Severity:            dbMatch.Severity,
				Confidence:          "high",
				Category:            dbMatch.Category,
				Match:               compositePath(filePath, table, column),
				MatchedText:         value,
				MatchedTextRedacted: value,
				Snippet:             fmt.Sprintf("%s -> %s", compositePath(filePath, table, column), trimValue(value, i.opts.MaxCellBytes)),
				Context:             formatSQLiteContext(table, column, rowContext),
				ContextRedacted:     formatSQLiteContext(table, column, rowContext),
				Explanation:         "This finding comes from a validated connection string or DSN stored in a bounded sample from a SQLite database.",
				Remediation:         "Remove embedded connection material from local SQLite stores, rotate exposed database credentials, and review why secrets were persisted in the application database.",
				Tags:                uniqueStrings(append([]string{"database", "sqlite", "db:type:sqlite-row", "db:type:config-credential"}, dbMatch.Tags...)),
				DatabaseTable:       table,
				DatabaseColumn:      column,
				DatabaseRowContext:  rowContext,
				DatabaseFilePath:    filePath,
			})
		}
		return out
	}

	if quality.Weak {
		return nil
	}

	severity := "medium"
	confidence := "medium"
	if quality.Strong {
		severity = "high"
		confidence = "high"
	}

	return []Match{{
		ID:                  "sqliteinspect.credentials.sensitive_value",
		Name:                "SQLite-Stored Sensitive Value",
		Description:         "A bounded SQLite row sample contained a high-signal credential, token, or secret value in an interesting column.",
		RuleType:            "content",
		SignalType:          "validated",
		Severity:            severity,
		Confidence:          confidence,
		Category:            "credentials",
		Match:               compositePath(filePath, table, column),
		MatchedText:         value,
		MatchedTextRedacted: value,
		Snippet:             fmt.Sprintf("%s -> %s", compositePath(filePath, table, column), trimValue(value, i.opts.MaxCellBytes)),
		Context:             formatSQLiteContext(table, column, rowContext),
		ContextRedacted:     formatSQLiteContext(table, column, rowContext),
		Explanation:         "This finding comes from a bounded SQLite table/column sample and only promotes values that look usable rather than placeholders.",
		Remediation:         "Remove embedded secrets from local SQLite databases, rotate exposed values, and review the application path that persisted the secret.",
		Tags: []string{
			"database",
			"sqlite",
			"db:type:sqlite-row",
			"value-quality:" + quality.Label,
		},
		DatabaseTable:      table,
		DatabaseColumn:     column,
		DatabaseRowContext: rowContext,
		DatabaseFilePath:   filePath,
	}}
}

func formatSQLiteContext(table, column, rowContext string) string {
	parts := []string{
		"SQLite table: " + strings.TrimSpace(table),
		"Column: " + strings.TrimSpace(column),
	}
	if strings.TrimSpace(rowContext) != "" {
		parts = append(parts, "Row context: "+strings.TrimSpace(rowContext))
	}
	return strings.Join(parts, "\n")
}

func normalizeCellValue(raw any, maxBytes int64) (string, int64, bool) {
	switch value := raw.(type) {
	case nil:
		return "", 0, false
	case string:
		trimmed := trimValue(value, maxBytes)
		if strings.TrimSpace(trimmed) == "" {
			return "", 0, false
		}
		return trimmed, int64(len(trimmed)), true
	case []byte:
		text := strings.TrimSpace(string(value))
		if text == "" {
			return "", 0, false
		}
		text = trimValue(text, maxBytes)
		return text, int64(len(text)), true
	default:
		return "", 0, false
	}
}

func buildRowContext(columns []string, values []any, contextSet map[string]struct{}, maxCellBytes int64) string {
	parts := make([]string, 0, len(contextSet))
	for idx, column := range columns {
		if _, ok := contextSet[column]; !ok {
			continue
		}
		value, _, ok := normalizeCellValue(values[idx], maxCellBytes)
		if !ok {
			continue
		}
		parts = append(parts, strings.TrimSpace(column)+"="+value)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

func maxInt(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}
