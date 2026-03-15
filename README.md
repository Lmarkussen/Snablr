# Snablr

Snablr is a Go-based SMB share triage tool for defensive review of Windows file shares. It discovers targets, enumerates accessible shares, walks files, applies YAML-driven rules, and produces operator-friendly findings in console, JSON, HTML, CSV, and Markdown formats.

The project is inspired by the general Snaffler workflow, but it is implemented as a clean Go codebase with a rules-first architecture, offline rule testing, resumable scans, and output/reporting intended for remediation and hygiene review.

## Feature Overview

- Domain-aware target discovery with LDAP and optional DFS discovery
- SMB share enumeration with recursive file walking
- YAML rule packs for filename, extension, and content detection
- Offline rule validation and fixture-based rule testing
- Scan planning and priority scoring for high-value shares and paths
- Concurrent file scanning with adaptive worker scaling
- Checkpoint and resume support for long-running scans
- Console, JSON, HTML, CSV, and Markdown exports
- Metrics, progress reporting, and scan timing visibility

## Architecture Overview

Snablr is organized around a few focused runtime modules:

- `discovery`
  - resolves targets from CLI input, files, LDAP, reachability checks, and optional DFS discovery
- `smb`
  - handles SMB connectivity, share enumeration, metadata collection, directory walking, and file reads
- `scanner`
  - evaluates filenames, extensions, and file content against loaded rules
- `rules`
  - loads, validates, manages, and tests YAML rules
- `planner`
  - prioritizes hosts, shares, and files before they reach the worker pool
- `output`
  - renders findings to console, JSON, HTML, CSV, and Markdown
- `state`
  - tracks checkpoint state for resumable scans
- `metrics`
  - records counters and phase timing data used by progress reporting and reports

## Repository Layout

```text
cmd/snablr/              CLI entrypoint
internal/app/            scan orchestration
internal/discovery/      LDAP, DFS, targets, reachability
internal/smb/            SMB client, shares, walker, reader
internal/scanner/        scan engine, workers, results
internal/rules/          YAML schema, loader, validator, tester
internal/planner/        priority planning
internal/output/         writers and reports
internal/state/          checkpoint and resume
internal/metrics/        counters and timers
internal/ui/             banner and progress display
configs/                 default runtime config and rule packs
docs/                    focused documentation
examples/                copyable examples and starter material
testdata/                safe synthetic fixtures for tests
```

## Installation

### Requirements

- Go `1.22+`
- Network access to reachable SMB targets on TCP `445`
- Valid credentials for the target environment

### Build From Source

```bash
git clone <repo-url>
cd snablr
make build
./bin/snablr version
```

### Build Directly With Go

```bash
go build -o bin/snablr ./cmd/snablr
./bin/snablr --help
```

### Install Into `GOBIN`

```bash
go install ./cmd/snablr
snablr version
```

## Quick Start

### Show Help

```bash
./bin/snablr --help
./bin/snablr scan --help
./bin/snablr rules validate --config configs/config.yaml
```

### Scan a Single Host

```bash
./bin/snablr scan \
  --targets 172.16.0.90 \
  --user 'DOMAIN\user' \
  --pass 'Password123!' \
  --output-format console
```

### Scan Using the Config File

```bash
./bin/snablr scan --config configs/config.yaml
```

### Let LDAP Discover Targets

```bash
./bin/snablr scan \
  --user 'DOMAIN\user' \
  --pass 'Password123!' \
  --output-format console
```

### Restrict Scope

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --share Finance \
  --exclude-share Backups \
  --path Policies/ \
  --max-depth 4
```

## Scan Examples

### Combined Report Output

```bash
./bin/snablr scan \
  --targets 172.16.0.90 \
  --user 'DOMAIN\user' \
  --pass 'Password123!' \
  --output-format all \
  --json-out results.json \
  --html-out report.html \
  --csv-out findings.csv \
  --md-out summary.md
```

### Long-Running Resumable Scan

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --checkpoint-file state/checkpoint.json \
  --resume \
  --max-scan-time 2h
```

### AD-Focused Scan

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --prioritize-ad-shares \
  --only-ad-shares
```

### DFS-Aware Scan

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --discover-dfs
```

## Rule Testing Examples

### List and Validate Rules

```bash
./bin/snablr rules list --config configs/config.yaml
./bin/snablr rules validate --config configs/config.yaml
```

### Show a Specific Rule

```bash
./bin/snablr rules show \
  --config configs/config.yaml \
  --id content.password_assignment_indicators
```

### Test a Single Rule File Against One Fixture

```bash
./bin/snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/passwords/sample.conf \
  --verbose
```

### Test a Rule Directory Against a Fixture Directory

```bash
./bin/snablr rules test-dir \
  --rules configs/rules/default \
  --fixtures testdata/rules/fixtures \
  --verbose
```

Rule testing exit codes:

- `0`: success, no matches
- `1`: validation or execution error
- `2`: one or more rules matched

## Output and Reporting

Snablr supports these primary output modes:

- `console`
- `json`
- `html`
- `all`

Optional sidecar exports:

- `--csv-out findings.csv`
- `--md-out summary.md`

### Output Examples

```bash
./bin/snablr scan --output-format console
./bin/snablr scan --output-format json --json-out results.json
./bin/snablr scan --output-format html --html-out report.html
./bin/snablr scan --output-format all --json-out results.json --html-out report.html --csv-out findings.csv --md-out summary.md
```

### HTML Report

The HTML report is a standalone triage artifact with:

- summary cards
- severity and category summaries
- collapsible finding groups
- sticky headers
- quick filtering
- share, DFS, SYSVOL, NETLOGON, and priority metadata

Screenshot placeholder:

- Add a future screenshot under `docs/images/` and reference it here once a public example scan is available.

## Configuration

The default configuration file is [configs/config.yaml](configs/config.yaml).

Example configuration:

```yaml
app:
  name: snablr
  log_level: info
  banner_path: internal/ui/assets/snablr.txt

scan:
  targets: []
  targets_file: ""
  username: "DOMAIN\\user"
  password: "Password123!"
  share: []
  exclude_share: []
  path: []
  exclude_path: []
  max_depth: 0
  worker_count: 0
  max_file_size: 10485760
  no_ldap: false
  domain: ""
  dc: ""
  base_dn: ""
  discover_dfs: false
  prioritize_ad_shares: true
  only_ad_shares: false
  max_scan_time: ""
  checkpoint_file: ""
  resume: false
  skip_reachability_check: false
  reachability_timeout_seconds: 3

rules:
  rules_directory: ""
  fail_on_invalid: false

output:
  output_format: all
  json_out: results.json
  html_out: report.html
  csv_out: findings.csv
  md_out: summary.md
  pretty: true
```

CLI flags override configuration values.

## Examples Directory

The [examples](examples) directory contains:

- [config.example.yaml](examples/config.example.yaml)
- [commands.md](examples/commands.md)
- [custom-rules](examples/custom-rules)
- [output-layout](examples/output-layout)

## Additional Documentation

- [Rule System](docs/rules.md)
- [Rule Tuning](docs/tuning.md)
- [Performance Notes](docs/performance.md)

## Development

Useful targets:

```bash
make build
make test
make lint
make release VERSION=1.0.0
```

Contribution guidance is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

This repository is licensed under the terms of the [MIT License](LICENSE).
