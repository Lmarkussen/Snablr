# Getting Started

> Current export workflow: scans persist SQLite and create RAW HTML by default;
> use `snablr find --html PATH --json PATH` for interpreted exports. The old
> scan output flags are removed and return migration errors.

Snablr is a defensive SMB share triage tool. It helps you discover likely Windows file share targets, enumerate accessible shares, scan filenames and file content with YAML rules, and produce review-friendly outputs for remediation work.

This guide is the shortest path from a fresh clone to a first useful run.

Snablr is intended for authorized defensive security work only. Use it only against systems and shares that you are explicitly permitted to assess.

All source-build commands below assume you are running from the repository root.

## What Snablr Does

At a high level, a Snablr scan does this:

1. load configuration and rule packs
2. collect targets from CLI input, target files, or LDAP discovery
3. test SMB reachability on TCP `445`
4. prioritize hosts, shares, and paths
5. enumerate shares and walk matching files
6. apply filename, extension, and content rules
7. write findings to console, JSON, HTML, CSV, or Markdown

The tool is intended for:

- file share hygiene review
- remediation-oriented triage
- rule tuning and coverage testing
- repeated scans with baseline comparison

## Requirements

- Go `1.24+`
- network access to target SMB hosts on TCP `445`
- valid SMB credentials for the target environment
- LDAP access and credentials if you want automatic domain discovery

## Build Snablr

Recommended local build:

```bash
make build
```

This creates:

- `bin/snablr`

Verify the build:

```bash
./bin/snablr version
./bin/snablr --help
```

Alternative build:

```bash
go build -o bin/snablr ./cmd/snablr
```

If `make` is not available, `go build ./...` is the simplest fallback build check.

Windows fallback:

```powershell
go build -o bin/snablr.exe ./cmd/snablr
.\bin\snablr.exe version
```

Note:
- `make build` injects version metadata.
- plain `go build` is fine for development, but usually reports `dev` / `unknown` metadata unless you provide ldflags.

## Verify Installation

Run:

```bash
./bin/snablr version
./bin/snablr --help
```

If `version` prints a version string and `--help` shows the command list, the binary is ready to use.

If the binary is not on your `PATH`, keep using `./bin/snablr` from the repo root.

## First Scan: Direct Host

Start with one explicit target:

```bash
./bin/snablr scan \
  --targets 10.0.0.5 \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --dbname results/snablr.db
```

Replace:

- `10.0.0.5` with a reachable Windows host
- `EXAMPLE\user` with a real account name
- `REPLACE_ME` with the real password at runtime

Expected behavior:

- the banner prints
- the rule pack loads and validates
- the target is checked for SMB reachability
- accessible shares are enumerated
- files are filtered, prioritized, and scanned
- findings are written to console, JSON, and HTML

Where results go in this example:

- `results.json`
- `report.html`

Open `report.html` in a browser after the scan finishes.

## Reopen Results In Finder

Every scan has an authoritative local SQLite state database. After a scan,
open its persisted findings without contacting SMB again:

```bash
./bin/snablr find --db /path/to/scan.db
./bin/snablr find --dbname /path/to/scan.db
```

When the scan used the default output workspace, `find` without `--db` checks
the same default `snablr.db` location:

```bash
./bin/snablr find
```

`--dbname` is an alias for Finder's `--db`; if both are supplied, they must
name the same file. With neither flag, Finder retains the scanner's existing
default database resolution.

Finder is read-only and uses category-first navigation:

1. choose a category or subcategory
2. select a logical discovery
3. inspect evidence and source provenance in the Details pane

The Details pane wraps long values and paths, including archive-member
references, and supports `Up`/`Down`, `j`/`k`, `PgUp`/`PgDn`, and focus changes
with `Tab`. Use `Enter` to open a selection, `Esc` to go back, and `Ctrl-C` to
exit Finder. Cross-file relationships are contextual observations; they are
not automatically verified username/password pairs.

The database distinguishes scanner-produced findings, persisted material rows,
logical discoveries, individual source observations, and contextual
correlations. Several observations can therefore appear under one logical
discovery while remaining available as separate evidence. Confirmed and
Review material keep their stored classification; Snablr does not authenticate
recovered values.

### Selecting and resetting scan databases

Use `--dbname` to select a SQLite database for a scan. A missing target is
created when the scan opens it; an existing target must be a valid Snablr
database and is handled with the normal resume/reuse semantics. The path is
never silently replaced with the default database:

```bash
snablr scan --targets HOST --dbname /path/to/customer.db
```

Use `--flushdb` only when an explicit, existing Snablr database should be
reset before a fresh scan:

```bash
snablr scan --targets HOST --flushdb /path/to/customer.db
```

Flush validation rejects missing, non-Snablr, incompatible, corrupt, directory,
symlink, and protected database targets. Reset clears scan history, findings,
evidence, relationships, bookmarks, and scope exclusions in one SQLite
transaction while retaining the validated schema and database file. A failed
validation or reset aborts before the scan starts. `--flushdb` cannot be
combined with `--resume`; `--dbname` and `--flushdb`, when both supplied, must
name the same file. New scans are displayed in Finder as
`scan-<sanitized-domain>-NNN`; numbering is persisted independently in each
database and is not shared across databases or carried across a flush.

## Interactive TUI Controls

Interactive terminal scans open the two-pane TUI unless `--no-tui` is used.
The left pane lists findings and the right pane shows wrapped, scrollable
evidence and provenance.

- `Ctrl-F` searches bounded SQLite-backed scan state across useful file/path,
  host/share, finding, credential, and evidence fields.
- `Ctrl-D` toggles a persistent file-centric bookmark; `Alt-D` opens bookmarks.
- `Alt-L` defers the current share to the end; `Alt-Q` opens the Share Queue.
- `Tab` switches pane focus. Use `Up`/`Down`, `j`/`k`, `PgUp`/`PgDn`, `g`/`G`,
  `Enter`, and `Esc` according to the focused list or detail view.
- `Ctrl-C` stops a foreground scan, leaves SQLite state resumable, and exits
  with status `130`.

Deferring a share does not skip it permanently. Safe in-flight work finishes,
completed file state is reused, and the scanner eventually returns to the
deferred share. Deferred queue order is not currently preserved across
Ctrl-C/resume. Daemon/attach mode is not implemented.

## First Scan: Config-Driven

For repeatable usage, start from one of the example configs.

Minimal direct-target example:

```bash
./bin/snablr scan --config examples/config.basic.yaml
```

That profile demonstrates:

- explicit targets
- placeholder credentials
- safe 15-worker default for SMB/file-server safety
- combined JSON and HTML output

## First Scan: Domain-Aware

If you do not provide targets, Snablr tries LDAP discovery by default unless `--no-ldap` is set.

```bash
./bin/snablr scan \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
```

Domain-aware example config:

```bash
./bin/snablr scan --config examples/config.domain.yaml
```

Expected behavior:

- Snablr tries to determine domain context
- it selects or uses a domain controller
- it queries LDAP for computer objects
- it merges discovered hosts into the target pipeline
- it tests reachability before SMB enumeration

If LDAP discovery fails, start over with a direct target scan first. That usually tells you whether the problem is discovery or SMB access.

## First Scan: Targeted Triage

If you want a fast, narrow validation run:

```bash
./bin/snablr scan \
  --targets fileserver.example.local \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --share Finance \
  --path Payroll/ \
  --max-depth 4 \
```

Or use the example targeted config:

```bash
./bin/snablr scan --config examples/config.targeted.yaml
```

## How LDAP Discovery Fits In

LDAP discovery is used when:

- `targets` is empty
- `targets_file` is empty
- `--no-ldap` is not set

The flow is:

1. detect domain context from environment, hostname, or resolver settings
2. discover a domain controller through DNS SRV lookups or `--dc`
3. query LDAP RootDSE for the default naming context
4. enumerate computer objects
5. merge those hosts into the normal scan pipeline

Useful overrides:

- `--no-ldap`
- `--domain`
- `--dc`
- `--base-dn`

## How SMB Scanning Fits In

Once targets are ready, Snablr:

1. tests TCP `445` reachability unless disabled
2. plans hosts and shares so likely high-value work happens first
3. connects over SMB with the provided credentials
4. enumerates accessible shares and share metadata
5. walks files with include/exclude filters applied early
6. reads file content only when content rules require it

This means:

- share and path filters reduce work before scanning
- large files are skipped early
- content reads are lazy instead of unconditional

## Expected Outputs

### Console

Best for live terminal use.

Example:

```text
[HIGH] content.password_assignment_indicators
Host: FILESERVER01
Share: Finance
File: \\FILESERVER01\Finance\web.config
Rule: Password Assignment Indicators
Category: credentials
Match: password=Secret123
```

### RAW HTML and Finder exports

Scans persist SQLite evidence and automatically write a collision-safe RAW HTML
report. Use `--no-outfile` to suppress only that report. Finder exports the
interpreted scope for automation or manual triage:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --dbname output/snablr.db

./bin/snablr find --db output/snablr.db --scan-id SCAN_ID \
  --html output/finder.html --json output/finder.json
```

## First Rule Validation

Before a live scan, validate the rule pack:

```bash
./bin/snablr rules validate --config configs/config.yaml
```

Test one rule file against one known fixture:

```bash
./bin/snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/content/password-assignment.conf \
  --verbose
```

## First Baseline / Diff Workflow

Run a scan and keep the JSON output:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --dbname results/snablr.db

./bin/snablr find --db results/snablr.db --scan-id SCAN_ID --json results.json
```

Later, compare a new run against that baseline:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --baseline results.json \
  --dbname results-new/snablr.db

./bin/snablr find --db results-new/snablr.db --scan-id SCAN_ID --json results-new.json
```

Or compare two existing JSON reports directly:

```bash
./bin/snablr diff --old results.json --new results-new.json
```

## Build And Release Notes

Local developer checks:

```bash
go build ./...
go test ./...
make build
make test
```

Version metadata check:

```bash
./bin/snablr version
```

If you want embedded version, commit, and build-date metadata, use `make build` or a release artifact instead of a plain ad-hoc `go build`.

## Next Steps

After the first successful run:

1. review `docs/configuration.md`
2. review `docs/rules.md`
3. review `docs/reporting.md`
4. add custom rules under `configs/rules/custom/`
5. use the automatic scan database for long scans
6. keep JSON output for later baseline comparisons
