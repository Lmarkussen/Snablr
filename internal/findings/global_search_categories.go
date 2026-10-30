package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type GlobalSearchCategory string

const (
	SearchAll     GlobalSearchCategory = "All"
	SearchCreds   GlobalSearchCategory = "Credentials"
	SearchFiles   GlobalSearchCategory = "Files & Paths"
	SearchContent GlobalSearchCategory = "Content & Configs"
	SearchHosts   GlobalSearchCategory = "Hosts & Shares"
	SearchOther   GlobalSearchCategory = "Other Evidence"
)

var globalSearchCategories = []GlobalSearchCategory{SearchAll, SearchCreds, SearchFiles, SearchContent, SearchHosts, SearchOther}

type categoryField struct{ label, expression string }
type categoryPopulation struct {
	category               GlobalSearchCategory
	kind, table, id, value string
	context, order         string
	fields                 []categoryField
	excludes               []string
}

func jsonSearchText(key string) string {
	return "CASE WHEN json_valid(payload) THEN COALESCE(CAST(json_extract(payload,'$." + key + "') AS TEXT),'') ELSE '' END"
}

func jsonArraySearchText(array, key string) string {
	return "CASE WHEN json_valid(payload) THEN COALESCE((SELECT group_concat(CAST(value AS TEXT),' ') FROM json_tree(payload,'$." + array + "') WHERE key='" + key + "'),'') ELSE '' END"
}

func categoryFields(names ...string) []categoryField {
	out := make([]categoryField, 0, len(names)/2)
	for i := 0; i < len(names); i += 2 {
		out = append(out, categoryField{names[i], names[i+1]})
	}
	return out
}

func categoryPopulations(hasDerived bool) []categoryPopulation {
	var specs []categoryPopulation
	add := func(category GlobalSearchCategory, kind, table, id, value, context, order string, fields []categoryField, excludes ...string) {
		specs = append(specs, categoryPopulation{category, kind, table, id, value, context, order, fields, excludes})
	}
	path := categoryFields("source path", "COALESCE(path,'')", "file path", jsonSearchText("file_path"), "archive path", jsonSearchText("archive_path"), "archive member path", jsonSearchText("archive_member_path"), "database file path", jsonSearchText("database_file_path"), "DFS namespace path", jsonSearchText("dfs_namespace_path"), "DFS link path", jsonSearchText("dfs_link_path"))
	content := categoryFields("matched text", jsonSearchText("matched_text"), "evidence snippet", jsonSearchText("snippet"), "evidence context", jsonSearchText("context"), "content match", jsonSearchText("match"), "database row context", jsonSearchText("database_row_context"), "persisted matched text", jsonSearchText("matched_text_redacted"), "persisted context", jsonSearchText("context_redacted"))
	hosts := categoryFields("hostname", "COALESCE(host,'')", "share name", "COALESCE(share,'')", "payload hostname", jsonSearchText("host"), "payload share", jsonSearchText("share"), "share description", jsonSearchText("share_description"))
	metadata := categoryFields("rule ID", "COALESCE(rule_id,'')", "classification", "COALESCE(category,'')", "payload rule ID", jsonSearchText("rule_id"), "payload classification", jsonSearchText("category"), "rule name", jsonSearchText("rule_name"), "severity", jsonSearchText("severity"), "confidence", jsonSearchText("confidence"), "triage class", jsonSearchText("triage_class"), "signal type", jsonSearchText("signal_type"), "match reason", jsonSearchText("match_reason"), "rule explanation", jsonSearchText("rule_explanation"), "rule remediation", jsonSearchText("rule_remediation"), "observation ID", jsonSearchText("observation_id"), "potential account", jsonSearchText("potential_account"), "source", jsonSearchText("source"), "database table", jsonSearchText("database_table"), "database column", jsonSearchText("database_column"), "matched rule IDs", jsonSearchText("matched_rule_ids"), "supporting signals", jsonSearchText("supporting_signals"), "tags", jsonSearchText("tags"))
	findingValue := "payload||char(10)||COALESCE(path,'')||char(10)||COALESCE(rule_id,'')||char(10)||COALESCE(category,'')||char(10)||COALESCE(host,'')||char(10)||COALESCE(share,'')"
	credentialValue := "payload||char(10)||COALESCE(identity,'')||char(10)||COALESCE(value,'')||char(10)||COALESCE(credential_key,'')"
	credentialPath := jsonSearchText("Path")
	for _, finding := range []struct{ kind, table, id, order, value, context string }{
		{"finding", "findings", "CAST(id AS TEXT)", "id", findingValue, "COALESCE(path,'')"},
		{"derived finding", "derived_findings", "correlation_key", "id", "payload||char(10)||correlation_key", jsonSearchText("file_path")},
	} {
		if finding.table == "derived_findings" && !hasDerived {
			continue
		}
		fp, fh, fm := path, hosts, metadata
		if finding.table == "derived_findings" {
			fp = path[1:]
			fh = hosts[2:]
			fm = metadata[2:]
		}
		add(SearchFiles, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, fp)
		add(SearchContent, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, content)
		add(SearchHosts, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, fh)
		add(SearchOther, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, fm)
		excluded := make([]string, 0, len(fp)+len(content)+len(fh)+len(fm))
		for _, group := range [][]categoryField{fp, content, fh, fm} {
			for _, field := range group {
				excluded = append(excluded, field.expression)
			}
		}
		add(SearchOther, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, categoryFields("other persisted finding details", "payload"), excluded...)
		if finding.table == "derived_findings" {
			add(SearchOther, finding.kind, finding.table, finding.id, finding.value, finding.context, finding.order, categoryFields("correlation key", "correlation_key"))
		}
	}
	add(SearchCreds, "credential", "credentials", "CAST(id AS TEXT)", credentialValue, credentialPath, "id", categoryFields("username", "COALESCE(identity,'')", "credential value", "COALESCE(value,'')", "credential type", "COALESCE(credential_type,'')", "payload username", jsonSearchText("Identity"), "payload credential value", jsonSearchText("value"), "key fingerprint", jsonSearchText("KeyFingerprint"), "key material", jsonSearchText("Material")))
	credentialEvidencePaths := jsonArraySearchText("Evidence", "path")
	add(SearchFiles, "credential", "credentials", "CAST(id AS TEXT)", credentialValue, credentialPath, "id", categoryFields("credential source path", credentialPath, "credential evidence paths", credentialEvidencePaths))
	add(SearchHosts, "credential", "credentials", "CAST(id AS TEXT)", credentialValue, credentialPath, "id", categoryFields("credential hostname", jsonSearchText("Host"), "credential share", jsonSearchText("Share")))
	add(SearchOther, "credential", "credentials", "CAST(id AS TEXT)", credentialValue, credentialPath, "id", categoryFields("credential record key", "COALESCE(credential_key,'')"))
	add(SearchOther, "credential", "credentials", "CAST(id AS TEXT)", credentialValue, credentialPath, "id", categoryFields("other credential details", "payload"), "COALESCE(identity,'')", "COALESCE(value,'')", "COALESCE(credential_type,'')", "COALESCE(credential_key,'')", jsonSearchText("Identity"), jsonSearchText("value"), jsonSearchText("KeyFingerprint"), jsonSearchText("Material"), credentialPath, credentialEvidencePaths, jsonSearchText("Host"), jsonSearchText("Share"))
	add(SearchFiles, "file", "files", "file_key", "path||char(10)||host||char(10)||share", "host||' / '||share", "file_key", categoryFields("file path", "path"))
	add(SearchHosts, "file", "files", "file_key", "path||char(10)||host||char(10)||share", "path", "file_key", categoryFields("file hostname", "host", "file share", "share"))
	add(SearchFiles, "member", "members", "member_key", "member_path||char(10)||COALESCE(provenance,'')||char(10)||parent_key||char(10)||member_key", "parent_key", "parent_key,member_key", categoryFields("member path", "member_path", "member key", "member_key", "parent path", "parent_key"))
	add(SearchOther, "member", "members", "member_key", "member_path||char(10)||COALESCE(provenance,'')||char(10)||parent_key||char(10)||member_key", "parent_key", "parent_key,member_key", categoryFields("member provenance", "COALESCE(provenance,'')"))
	add(SearchFiles, "access observation", "access_observations", "context_id", "access_result||char(10)||context_id||char(10)||file_key", "context_id", "context_id,file_key", categoryFields("file key", "file_key"))
	add(SearchOther, "access observation", "access_observations", "context_id", "access_result||char(10)||context_id||char(10)||file_key", "context_id", "context_id,file_key", categoryFields("access context", "context_id", "access result", "access_result"))
	add(SearchHosts, "share", "shares", "host||'/'||share", "host||char(10)||share", "host", "host,share", categoryFields("share hostname", "host", "share name", "share"))
	add(SearchHosts, "target", "targets", "host", "host||char(10)||status", "host", "host", categoryFields("target hostname", "host"))
	add(SearchOther, "target", "targets", "host", "host||char(10)||status", "host", "host", categoryFields("target status", "status"))
	correlationValue := "payload||char(10)||correlation_key"
	correlationPath := jsonArraySearchText("sources", "path")
	correlationContainer := jsonArraySearchText("sources", "container")
	correlationHost := jsonArraySearchText("sources", "host")
	correlationShare := jsonArraySearchText("sources", "share")
	add(SearchCreds, "correlation", "correlations", "correlation_key", correlationValue, "correlation_key", "correlation_key", categoryFields("correlated username", jsonSearchText("identity"), "correlated credential type", jsonSearchText("credential_type")))
	add(SearchFiles, "correlation", "correlations", "correlation_key", correlationValue, "correlation_key", "correlation_key", categoryFields("correlated source path", correlationPath, "correlated container path", correlationContainer))
	add(SearchHosts, "correlation", "correlations", "correlation_key", correlationValue, "correlation_key", "correlation_key", categoryFields("correlated hostname", correlationHost, "correlated share", correlationShare))
	add(SearchOther, "correlation", "correlations", "correlation_key", correlationValue, "correlation_key", "correlation_key", categoryFields("correlation key", "correlation_key", "correlation type", jsonSearchText("type"), "correlation domain", jsonSearchText("domain"), "correlation confidence", jsonSearchText("confidence"), "confidence rationale", jsonSearchText("confidence_rationale")))
	add(SearchOther, "correlation", "correlations", "correlation_key", correlationValue, "correlation_key", "correlation_key", categoryFields("other correlation details", "payload"), "correlation_key", jsonSearchText("identity"), jsonSearchText("credential_type"), correlationPath, correlationContainer, correlationHost, correlationShare, jsonSearchText("type"), jsonSearchText("domain"), jsonSearchText("confidence"), jsonSearchText("confidence_rationale"))
	add(SearchOther, "scan metadata", "scans", "scan_id", "scan_id||char(10)||COALESCE(snablr_version,'')||char(10)||COALESCE(semantics,'')||char(10)||status", "scan_id", "scan_id", categoryFields("scan ID", "scan_id", "scanner version", "COALESCE(snablr_version,'')", "scan semantics", "COALESCE(semantics,'')", "scan status", "status"))
	return specs
}

// GlobalSearchCategoryPage keeps each category on the same bounded, cancellable
// SQLite page path as the existing All search. A finding can match once per
// category, based on the persisted field that matched.
func (p *Provider) GlobalSearchCategoryPage(ctx context.Context, scanID, query string, category GlobalSearchCategory, phase, offset, limit int) ([]GlobalSearchResult, int, int, bool, error) {
	if category == "" {
		category = SearchAll
	}
	if category == SearchAll {
		rows, nextPhase, nextOffset, done, err := p.GlobalSearchPage(ctx, scanID, query, phase, offset, limit)
		if err == nil {
			for i := range rows {
				rows[i].Field = allSearchMatchedField(rows[i], query)
			}
		}
		return rows, nextPhase, nextOffset, done, err
	}
	if limit < 1 || limit > globalSearchPageSize || phase < 0 || offset < 0 {
		return nil, 0, 0, false, fmt.Errorf("invalid global search page bounds")
	}
	if query == "" {
		return nil, 0, 0, true, nil
	}
	var specs []categoryPopulation
	for _, spec := range categoryPopulations(p.hasDerivedFindings) {
		if spec.category == category {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return nil, 0, 0, false, fmt.Errorf("unknown global search category %q", category)
	}
	for phase < len(specs) {
		spec := specs[phase]
		var cases, predicates, exclusions []string
		args := make([]any, 0, 2*len(spec.fields)+len(spec.excludes)+3)
		for _, field := range spec.fields {
			cases = append(cases, "WHEN snablr_contains("+field.expression+",?) THEN '"+field.label+"'")
			args = append(args, query)
		}
		args = append(args, scanID)
		for _, field := range spec.fields {
			predicates = append(predicates, "snablr_contains("+field.expression+",?)")
			args = append(args, query)
		}
		for _, expression := range spec.excludes {
			exclusions = append(exclusions, "snablr_contains("+expression+",?)")
			args = append(args, query)
		}
		where := "(" + strings.Join(predicates, " OR ") + ")"
		if len(exclusions) > 0 {
			where += " AND NOT (" + strings.Join(exclusions, " OR ") + ")"
		}
		args = append(args, limit, offset)
		sqlQuery := "SELECT '" + spec.kind + "'," + spec.id + ",CASE " + strings.Join(cases, " ") + " END," + spec.value + "," + spec.context + " FROM " + spec.table + " WHERE scan_id=? AND " + where + " ORDER BY " + spec.order + " LIMIT ? OFFSET ?"
		rows, err := p.db.QueryContext(ctx, sqlQuery, args...)
		if err != nil {
			return nil, 0, 0, false, fmt.Errorf("search %s persisted Finder data: %w", category, err)
		}
		out := make([]GlobalSearchResult, 0, limit)
		for rows.Next() {
			var result GlobalSearchResult
			if err := rows.Scan(&result.Kind, &result.ID, &result.Field, &result.Value, &result.Context); err != nil {
				_ = rows.Close()
				return nil, 0, 0, false, err
			}
			out = append(out, result)
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return nil, 0, 0, false, err
		}
		if closeErr != nil {
			return nil, 0, 0, false, closeErr
		}
		if len(out) == limit {
			return out, phase, offset + len(out), false, nil
		}
		phase++
		offset = 0
		if len(out) > 0 {
			return out, phase, 0, phase == len(specs), nil
		}
	}
	return nil, phase, 0, true, nil
}

func allSearchMatchedField(result GlobalSearchResult, query string) string {
	contains := func(value string) bool {
		return strings.Contains(strings.ToLower(value), strings.ToLower(query))
	}
	if result.Kind == "file" && contains(result.Value) {
		return "file path"
	}
	if result.Kind == "finding" && contains(result.Context) {
		return "source path"
	}
	if result.Kind == "target" && contains(result.Context) {
		return "target hostname"
	}
	if result.Kind == "scan metadata" && contains(result.Context) {
		return "scan ID"
	}
	if result.Kind == "credential" && result.Field != "credential details" {
		return result.Field
	}
	if result.Kind == "finding" || result.Kind == "derived finding" || result.Kind == "credential" || result.Kind == "correlation" {
		payload := result.Value
		if result.Kind == "credential" {
			payload, _, _ = strings.Cut(payload, "\n")
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal([]byte(payload), &fields) == nil {
			keys := make([]string, 0, len(fields))
			for key := range fields {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				var value any
				if json.Unmarshal(fields[key], &value) == nil && contains(fmt.Sprint(value)) {
					return strings.ReplaceAll(key, "_", " ")
				}
			}
		}
	}
	return result.Field
}
