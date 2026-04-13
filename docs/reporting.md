# Reporting

Snablr supports several output formats so the same scan can be used for live operator feedback, automation, post-scan triage, and follow-up workflows.

Supported outputs:

- console
- JSON
- HTML
- CSV
- Markdown
- curated `creds.txt`

## Output Modes

The primary output mode is controlled with `output_format`.

Supported primary modes:

- `console`
- `json`
- `html`
- `all`

You can also combine primary export modes explicitly:

- `html,json`
- `console,json`
- `console,html`

Optional sidecar exports:

- `--csv-out findings.csv`
- `--md-out summary.md`
- `--creds-out creds.txt`
- `--scanned-targets-out scanned_targets.txt`

Example:

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/results.json \
  --html-out output/report.html \
  --csv-out output/findings.csv \
  --md-out output/summary.md \
  --creds-out output/creds.txt \
  --scanned-targets-out output/scanned_targets.txt
```

In that example, Snablr writes:

- JSON to `output/results.json`
- HTML to `output/report.html`
- CSV to `output/findings.csv`
- Markdown to `output/summary.md`
- curated credentials to `output/creds.txt`
- target audit to `output/scanned_targets.txt`

The `creds.txt` export is intentionally narrow. It includes only primary, high-confidence findings with usable credential material. Supporting artifacts, weak review items, and placeholder/example values are excluded.

The `scanned_targets.txt` export is an audit aid. It records the targets Snablr discovered or accepted, whether they were reachable, and whether they were actually planned for scanning.

## Console Output

Console output is designed for live terminal triage.

When stdout/stderr are attached to an interactive terminal, Snablr now uses a Bubble Tea TUI instead of line-by-line stdout printing.

Before the TUI starts, Snablr runs required preflight credential validation for the active scan mode.

- scans that rely on LDAP or DFS discovery validate those credentials before the TUI opens
- invalid required credentials abort the scan immediately
- discovery-based scans then show target discovery and reachability progress in plain console output
- the TUI only starts after preflight succeeds and target preparation is complete

Layout:

- left pane
  finding stream, scan progress, and current activity
- right pane
  evidence and detail for the currently selected finding

The separation is deliberate:

- the left pane shows metadata only
- raw evidence, snippets, matched values, archive member context, and SQLite row context stay in the right pane
- by default, the live findings pane shows primary findings only
- low-value supporting artifacts such as generic config/script hits or supporting-only metadata observations remain available to correlation and exported reports, but they do not flood the default live stream

Controls:

- `up` / `down`
- `j` / `k`
- `g` / `G`
- `PgUp` / `PgDn`
- `q` warns during an active scan

Implementation note:

- the live TUI consumes bounded writer state on a timer instead of receiving one blocking UI event per finding
- this keeps the scan path from stalling if the terminal UI falls behind under heavy finding volume
- the TUI remains open after the scan completes so you can review the final findings state, and closes when you exit it explicitly

Mode selection note:

- the TUI is the default live interface for interactive runs, regardless of whether you also request HTML, JSON, CSV, Markdown, or `creds.txt` exports
- export flags control report generation only
- `--no-tui` is the explicit switch that disables the TUI and falls back to plain console output in an interactive terminal

Use console when you want:

- immediate feedback during a scan
- interactive review while watching progress
- evidence inspection without exposing raw matched content in the scrolling findings list

If the scan is not attached to an interactive terminal, Snablr falls back to the plain line-oriented console writer.

The same visibility rule applies there:

- default live console output shows primary findings only
- supporting/contextual observations are retained for correlation, JSON, and HTML output

The HTML report now uses a split view:

- primary findings render in the main report body
- supporting findings move into a separate collapsed supporting-context section

This keeps the default report focused on actionable evidence while still preserving weaker artifacts for correlation and manual follow-up.

If you want the old plain stdout console output even in an interactive terminal, run the scan with:

- `--no-tui`

## JSON Output

JSON is the best format for automation, scripting, archival, and diff workflows.

It includes:

- scan summary metadata
- phase metrics and timing data
- category summaries
- diff summary when a baseline is provided
- seeded validation summary when `--seed-manifest` is provided
- confidence breakdowns for why each finding scored the way it did
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
- `archive_path`
- `archive_member_path`
- `archive_local_inspect`
- `database_file_path`
- `database_table`
- `database_column`
- `database_row_context`
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
- access-path summaries for correlated high-value clusters
- scan timing and metric summaries
- severity summary
- category summary
- host summary
- collapsible grouped findings
- sticky table headers
- inline filtering
- severity, confidence, source, AD-share, and priority badges
- rule explanation and remediation guidance
- synthetic high-confidence correlation findings when strongly related artifacts co-occur, such as `NTDS.DIT + SYSTEM` or a private key with nearby client-auth artifacts
- synthetic high-confidence correlation findings when DPAPI `Protect` material co-occurs with `Credentials` or `Vault` paths under the same profile context
- synthetic high-confidence backup exposure findings when multiple credential-relevant system artifacts co-occur under the same exact backup family
- synthetic browser credential-store exposure findings when exact paired browser profile artifacts co-occur under the same normalized browser profile context
- synthetic AWS credential profile findings when exact `.aws/credentials` and `.aws/config` artifacts co-occur under the same normalized profile context
- synthetic certificate bundle findings when exact `.pfx` or `.p12` artifacts co-occur with nearby password evidence in the same directory context
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

### 3.5. Review Top Access Paths

The top access-path section is a concise operator summary built from already-correlated findings.
It is ranked so you can act on the most likely compromise routes first.

Typical entries include:

- AD compromise paths
- system-state backup exposure
- Windows credential-store exposure
- browser credential-store exposure
- private key or client-auth bundles
- database or app credential clusters
- archive-derived credential clusters

Each card tells you:

- what kind of access path was identified
- the exploitability score and priority tier
- why it matters
- which host/share it came from
- the primary anchor path
- how complete the artifact set looks
- the related artifacts that caused promotion

Ranking notes:

- ranking is deterministic and based on already-correlated findings
- stronger known combinations such as `NTDS.dit + SYSTEM` sort above weaker paired profile artifacts
- archive-derived clusters are identified explicitly, but they still keep their underlying access-path type in context

### 3.6. Review Suppressed Findings

The suppressed-findings section is an audit view for explicit allowlist matches.

It shows:

- how many findings were suppressed
- which suppression rules matched
- why those suppressions exist
- sample suppressed findings with host, share, path, and finding rule

Important behavior:

- suppressed findings are hidden from the main visible finding list
- they do not disappear silently
- suppression is applied before correlated access-path summaries are built, so known-benign findings do not inflate ranked access paths
- suppression is explicit and config-driven; Snablr does not hide findings through undocumented heuristics

This section is meant to answer the practical question:

- "What are the most likely routes to real access?"

### 4. Read A Finding Row

Each finding row typically gives you:

- severity and confidence
- host and share location
- file path
- archive path and inner member path when the evidence came from inside a supported archive such as `.zip`, `.tar`, `.tar.gz`, `.tgz`, or Office Open XML containers
- database file, table, column, and row context when the evidence came from bounded SQLite inspection
- rule name and category
- match snippet
- rule explanation
- remediation guidance
- source context such as DFS, SYSVOL, NETLOGON, or planner priority
- confidence breakdown covering content signal strength, value quality, correlation contribution, and path/context contribution

Interpretation tips:

- severity tells you urgency
- confidence tells you likely signal quality
- the snippet shows the evidence that triggered the rule
- the explanation tells you why the rule exists
- the remediation guidance tells you what defensive action to consider next

Archive finding notes:

- archive-derived findings use a combined path like `loot.zip!configs/web.config`
- tar-derived findings use the same combined path format, for example `deploy-configs.tar.gz!app/.env`
- private key and client-auth findings inside inspected archives use the same combined path format, for example `ops-recovery.tgz!keys/id_rsa`
- Windows profile credential-store findings inside inspected archives use the same combined path format, for example `profile-backup.zip!Users/Alice/AppData/Roaming/Microsoft/Credentials/ABCD1234`
- JSON also preserves `archive_path` and `archive_member_path` separately
- `archive_local_inspect: true` means the outer archive was inspected locally by Snablr after being read, rather than unpacked on the remote target
- the confidence breakdown tells you why a finding stayed low-value or was promoted

SQLite finding notes:

- SQLite-derived findings use a combined path like `app.db::users.password`
- JSON also preserves `database_file_path`, `database_table`, `database_column`, and `database_row_context` separately
- these findings come from bounded local SQLite sampling, not full database dumping
- report-time correlation may promote a SQLite finding when nearby config or backup evidence reinforces it

Backup exposure notes:

- exact backup-family paths use the normal finding flow and category summaries
- when multiple hive or AD database artifacts co-occur under the same exact backup family, the HTML report also surfaces an access-path summary such as `System-state backup exposure`
- the confidence breakdown for those findings explains the backup-family contribution separately from the correlation contribution

Browser credential-store notes:

- standalone browser profile artifacts are intentionally low-visibility because Snablr does not parse or decrypt browser stores in this phase
- when exact paired artifacts such as Firefox `logins.json + key4.db` or Chromium `Login Data + Cookies` co-occur under the same normalized browser profile context, the report can surface a correlated access-path summary
- these findings explain that credential or session extraction may be possible, but that Snablr did not perform extraction itself

### 5. Use Filters And Groups

The quick filter is useful for narrowing by:

- hostname
- share
- rule ID
- category
- path fragment
- tags

Structured filters are also available in the standalone HTML report. They can be combined with the quick filter to narrow by:

- severity
- confidence
- category
- source
- host/share
- signal type
- correlated findings only
- actionable findings only
- hide config-only findings
- hide medium-or-lower confidence findings
- reset filters back to the full report

Practical examples:

- filter on `SYSVOL` for AD-focused review
- filter on `credentials` to focus on likely hardcoded secrets
- filter on one hostname to review a single server in isolation

The HTML view updates visible finding groups in place, so it is practical to move between:

- only actionable findings
- only correlated/high-confidence findings
- everything except lower-confidence review noise in the primary section

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

The JSON report also includes:

- `performance`
  Files scanned, findings, duration, and files-per-second
- `performance_comparison`
  Baseline deltas when `--baseline` is used
- `validation`
  Seeded expected-versus-observed summary when `--seed-manifest` is used
- `validation_mode`
  Diagnostic summary when `--validation-mode` is enabled

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
