# Reporting

Snablr supports several output formats so operators can use the same scan for both live triage and later review.

Supported outputs:

- console
- JSON
- HTML
- CSV
- Markdown

## Output Modes

The primary output mode is selected with `output_format`.

Supported primary modes:

- `console`
- `json`
- `html`
- `all`

Optional sidecar exports:

- `--csv-out findings.csv`
- `--md-out summary.md`

Example:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/results.json \
  --html-out output/report.html \
  --csv-out output/findings.csv \
  --md-out output/summary.md
```

## Console Output

Console output is designed for live operator feedback.

It includes:

- severity
- host
- share
- share metadata when available
- source metadata such as LDAP or DFS
- file path
- rule name and category
- match text or snippet
- concise explanation and remediation notes

Use console output when you want:

- immediate feedback during a run
- interactive terminal triage
- a simple stream of findings while watching progress

## JSON Output

JSON output is best for automation, pipelines, or downstream processing.

It includes:

- scan summary metadata
- metrics and phase timings
- category summaries
- one structured object per finding

Common JSON finding fields include:

- `host`
- `share`
- `share_type`
- `share_description`
- `file_path`
- `rule_id`
- `rule_name`
- `severity`
- `confidence`
- `category`
- `tags`
- `match`
- `match_snippet`
- `match_reason`
- `rule_explanation`
- `rule_remediation`
- `source`
- `dfs_namespace_path`
- `dfs_link_path`
- `from_sysvol`
- `from_netlogon`
- `priority`
- `priority_reason`

Use JSON when you need:

- integration with another tool
- archival of structured results
- scripting or filtering after the scan

## HTML Output

The HTML report is a standalone post-scan review artifact. It is meant to be easy to hand to another operator, reviewer, or remediation owner.

It includes:

- summary cards
- timing and metrics sections
- severity summaries
- category summaries
- collapsible finding groups
- sticky headers
- inline filtering
- severity, source, AD-share, and priority badges
- rule explanation and remediation guidance

Use HTML when you need:

- a browser-friendly review artifact
- grouped triage by category
- a portable report with no external assets

## CSV Output

CSV output is a flat findings export intended for spreadsheets and ad hoc sorting.

It includes one row per finding with common fields such as:

- host
- share
- share metadata
- file path
- rule ID and name
- severity and confidence
- category
- tags
- match and snippet
- source metadata

Use CSV when you need:

- quick spreadsheet filtering
- import into ticketing or inventory workflows
- a compact flat export for sharing

## Markdown Output

Markdown output is a lightweight summary intended for notes, tickets, or lightweight handoff.

It includes:

- scan summary
- category summary
- concise findings table

Use Markdown when you need:

- a human-readable summary in a repository or ticket
- a scan recap for notes
- a portable text artifact without a browser

## Report Fields

While formats differ, Snablr findings generally carry the same core data:

### Identity

- host
- share
- share type
- share description
- file path

### Detection

- rule ID
- rule name
- severity
- confidence
- category
- tags

### Evidence

- match
- match snippet
- match reason

### Guidance

- rule explanation
- rule remediation
- category-level remediation guidance

### Context

- source
- DFS metadata
- SYSVOL or NETLOGON markers
- planner priority and priority reason

## HTML Triage Workflow

A practical HTML review flow:

1. open the report in a browser
2. start with the summary cards to understand scale
3. check severity counts to decide how to triage first
4. review category summaries to identify the riskiest buckets
5. open the highest-severity category groups first
6. use the quick filter box to narrow by host, share, rule, path, or tag
7. use match reason, rule explanation, and remediation fields to decide what needs action
8. export or reference JSON, CSV, or Markdown as needed for follow-up

Useful patterns:

- filter on a hostname to review one server at a time
- filter on `SYSVOL` or `NETLOGON` for AD-focused review
- filter on a tag like `cloud`, `credentials`, or `business-sensitive`
- sort follow-up work by severity and category rather than by raw file count

## Choosing The Right Output Combination

Recommended combinations:

- console only
  - fast live feedback during a short targeted run

- JSON only
  - automation and structured downstream handling

- HTML only
  - standalone manual review

- all + CSV + Markdown
  - best all-round option for larger scans and handoff
