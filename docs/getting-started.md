# Getting Started

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
  --output-format all \
  --json-out results.json \
  --html-out report.html
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

## First Scan: Config-Driven

For repeatable usage, start from one of the example configs.

Minimal direct-target example:

```bash
./bin/snablr scan --config examples/config.basic.yaml
```

That profile demonstrates:

- explicit targets
- placeholder credentials
- adaptive worker scaling
- combined JSON and HTML output

## First Scan: Domain-Aware

If you do not provide targets, Snablr tries LDAP discovery by default unless `--no-ldap` is set.

```bash
./bin/snablr scan \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --output-format console
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
  --output-format console
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

### JSON

Best for automation and diff/baseline workflows.

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --output-format json \
  --json-out results.json
```

### HTML

Best for manual triage and remediation review.

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --output-format html \
  --html-out report.html
```

### Combined Output

Recommended for most real runs:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/results.json \
  --html-out output/report.html \
  --csv-out output/findings.csv \
  --md-out output/summary.md
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
  --output-format all \
  --json-out results.json \
  --html-out report.html
```

Later, compare a new run against that baseline:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --baseline results.json \
  --output-format all \
  --json-out results-new.json \
  --html-out report-new.html
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
5. use checkpoints for long scans
6. keep JSON output for later baseline comparisons
