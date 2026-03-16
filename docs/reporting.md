# Reporting

Snablr supports several output formats so the same scan can be used for live operator feedback, automation, post-scan triage, and follow-up workflows.

Supported outputs:

- console
- JSON
- HTML
- CSV
- Markdown

## Output Modes

The primary output mode is controlled with `output_format`.

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
snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/results.json \
  --html-out output/report.html \
  --csv-out output/findings.csv \
  --md-out output/summary.md
```

In that example, Snablr writes:

- JSON to `output/results.json`
- HTML to `output/report.html`
- CSV to `output/findings.csv`
- Markdown to `output/summary.md`

## Console Output

Console output is designed for live terminal triage.

It includes:

- severity
- host
- share
- share type and description when available
- file path
- rule name and category
- match text or snippet
- concise explanation and remediation notes
- source context such as DFS, SYSVOL, or NETLOGON

Use console when you want:

- immediate feedback during a scan
- interactive review while watching progress
- simple operator-friendly output without opening a report file

## JSON Output

JSON is the best format for automation, scripting, archival, and diff workflows.

It includes:

- scan summary metadata
- phase metrics and timing data
- category summaries
- diff summary when a baseline is provided
- one structured object per finding

Common finding fields:

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
- `diff_status`
- `changed_fields`

Use JSON when you need:

- downstream parsing
- baseline comparison
- automation or CI workflows
- reproducible result storage

## HTML Output

The HTML report is the main post-scan review artifact. It is standalone, portable, and designed for a browser-based triage workflow.

It includes:

- summary cards
- scan timing and metric summaries
- severity summary
- category summary
- host summary
- collapsible grouped findings
- sticky table headers
- inline filtering
- severity, confidence, source, AD-share, and priority badges
- rule explanation and remediation guidance
- diff summary when a baseline is provided

Use HTML when you need:

- a review artifact for another analyst
- a browser-friendly grouped report
- a standalone file for remediation review

After a scan, open the file you passed to `--html-out` in a browser.

## CSV Output

CSV is a flat export with one row per finding.

Typical fields include:

- host
- share
- share metadata
- file path
- rule ID and rule name
- severity and confidence
- category
- tags
- match and snippet
- source metadata

Use CSV when you need:

- spreadsheet filtering
- import into ticketing or inventory workflows
- a compact flat handoff format

## Markdown Output

Markdown is a concise text summary for notes, tickets, and lightweight sharing.

It typically includes:

- scan summary
- category summary
- a compact findings table

Use Markdown when you need:

- a lightweight narrative summary
- repository or ticket attachments
- a readable text artifact without a browser

## How To Interpret The HTML Report

There is no committed screenshot in the repository yet, so the report is described directly here.

### 1. Start With The Summary Cards

The summary cards tell you:

- how many hosts were scanned
- how many shares were enumerated
- how many files were visited
- how many findings were produced
- how many files were skipped
- how many read errors occurred
- how long the scan took

This helps you understand whether you are reviewing a small targeted run or a broad environment-wide pass.

### 2. Check Severity Summary

The severity summary tells you where to start:

- `critical` and `high` findings usually deserve first review
- a large number of `medium` findings may indicate a noisy but useful rule category
- many `low` findings may point to tuning opportunities

### 3. Review Category Summary

Category summary helps you answer:

- are most findings credentials-related?
- are you mostly seeing configuration review hits?
- is the result set dominated by one noisy category?

This is often the fastest way to prioritize remediation work.

### 4. Read A Finding Row

Each finding row typically gives you:

- severity and confidence
- host and share location
- file path
- rule name and category
- match snippet
- rule explanation
- remediation guidance
- source context such as DFS, SYSVOL, NETLOGON, or planner priority

Interpretation tips:

- severity tells you urgency
- confidence tells you likely signal quality
- the snippet shows the evidence that triggered the rule
- the explanation tells you why the rule exists
- the remediation guidance tells you what defensive action to consider next

### 5. Use Filters And Groups

The quick filter is useful for narrowing by:

- hostname
- share
- rule ID
- category
- path fragment
- tags

Practical examples:

- filter on `SYSVOL` for AD-focused review
- filter on `credentials` to focus on likely hardcoded secrets
- filter on one hostname to review a single server in isolation

## Diff / Baseline Reporting

Snablr supports repeated-scan comparison through JSON baselines.

Two ways to use it:

### Compare During A New Scan

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --baseline previous-results.json \
  --output-format all \
  --json-out results.json \
  --html-out report.html
```

### Compare Two Existing Reports

```bash
snablr diff --old previous-results.json --new results.json
```

Diff categories:

- `new`
- `removed`
- `changed`
- `unchanged`

When a baseline is supplied:

- JSON includes `diff_summary`
- HTML includes diff summary cards and finding highlights

This is useful when you want to focus on what changed since the last run rather than re-reading the full dataset.

## Recommended Output Combinations

### Console Only

Use for:
- quick targeted validation runs

### JSON Only

Use for:
- automation
- scripts
- baseline storage

### HTML Only

Use for:
- manual browser review

### `all` Plus CSV And Markdown

Use for:
- larger scans
- analyst handoff
- JSON automation plus HTML triage plus lightweight exports
