# Snablr

Snablr is a Go-based SMB share triage tool for defensive review of Windows file shares. It discovers likely scan targets, enumerates accessible shares, walks files, applies YAML-driven detection rules, and produces structured findings for remediation and hygiene review.

The project is inspired by the general Snaffler workflow, but it is implemented as a clean Go codebase with a rules-first design, resumable scans, offline rule testing, and reporting aimed at defensive triage rather than exploitation.

## Authorized Use

Snablr is intended for authorized defensive security work only. Run it only against systems, shares, and directories that you own or have explicit permission to assess.

## Feature Overview

- Domain-aware target discovery with LDAP and optional DFS discovery
- Automatic LDAP-to-LDAPS fallback when simple bind hits common signing requirements
- SMB share enumeration, metadata collection, and recursive file walking
- YAML rule packs for filename, extension, and content matching
- Built-in database artifact and connection-material inspection for common enterprise formats
- Limited local-only SQLite inspection for bounded credential, token, and connection-material review
- High-signal private key and client-auth artifact coverage, including exact extensionless SSH private key names
- Correlated PKCS#12 certificate bundle exposure when `.pfx` or `.p12` artifacts appear with nearby password evidence
- High-signal AWS shared-profile artifact coverage for `.aws/credentials` and `.aws/config`, including real credential bundle validation
- Exact Windows credential-store path coverage for `Credentials`, `Vault`, and `Protect` profile families
- Exact Windows backup-exposure path coverage for `WindowsImageBackup`, `System Volume Information`, `RegBack`, and Windows repair hive families
- Exact browser profile credential-store artifact coverage for Firefox and Chromium-family profile stores
- Limited local-side `.zip` inspection with defensive size and member limits
- Rule validation, fixture-based testing, and custom rule overlays
- Prioritized scan planning for high-value targets, shares, and paths
- Concurrent file scanning with adaptive worker scaling
- Checkpoint and resume support for longer scans
- Bubble Tea live terminal UI for interactive console scans, plus JSON, HTML, CSV, and Markdown outputs
- Structured HTML report filtering, confidence breakdowns, and seeded validation summaries
- Explicit suppression and allowlisting with auditable suppressed-finding summaries
- Deterministic scan profiles for default, validation, and aggressive bounded-inspection modes
- Ranked top access-path summaries for correlated AD, backup, AWS credential profile, credential-store, private-key, browser, and app/database exposure clusters
- Baseline and diff mode for repeated scans and change tracking
- Synthetic lab seeding and manifest-based verification with `snablr-seed`

## Architecture Summary

Snablr is organized around a small set of focused modules:

- `discovery`
  Resolves targets from CLI input, target files, LDAP, reachability checks, and optional DFS discovery.
- `smb`
  Handles SMB connectivity, share enumeration, share metadata, directory walking, and file reads.
- `rules`
  Loads, validates, manages, and tests YAML rules.
- `planner`
  Prioritizes hosts, shares, and file paths before work reaches the scanner.
- `scanner`
  Applies filename, extension, and content rules to file metadata and content, including limited `.zip` member inspection.
- `output`
  Renders findings to console, JSON, HTML, CSV, and Markdown.
- `state`
  Stores checkpoint data for resumable scans.
- `metrics`
  Tracks counters and phase timing for progress and reports.

## Installation

### Requirements

- Go `1.24+`
- `make` if you want to use the convenience build targets
- Network access to target SMB hosts on TCP `445`
- Valid SMB credentials for target shares
- LDAP connectivity and credentials if you want automatic domain discovery

### Download A Release Binary

Prebuilt archives are published on GitHub releases.

Examples:

- `snablr_v1.0.0_linux_amd64.tar.gz`
- `snablr_v1.0.0_linux_arm64.tar.gz`
- `snablr_v1.0.0_darwin_amd64.tar.gz`
- `snablr_v1.0.0_darwin_arm64.tar.gz`
- `snablr_v1.0.0_windows_amd64.zip`

Linux/macOS archives contain:

- `snablr`
- `README.md`
- `LICENSE`

Windows archives contain:

- `snablr.exe`
- `README.md`
- `LICENSE`

Quick verification after download:

```bash
./snablr version
```

On Windows PowerShell:

```powershell
.\snablr.exe version
```

### Build From Source

Run these commands from the repository root.

Recommended local build:

```bash
git clone https://github.com/Lmarkussen/Snablr.git
cd Snablr
make build
./bin/snablr version
```

Direct Go build:

```bash
go build -o bin/snablr ./cmd/snablr
./bin/snablr --help
```

Build the lab seeder:

```bash
go build -o bin/snablr-seed ./cmd/snablr-seed
./bin/snablr-seed --help
```

If you are on Windows and do not use `make`, use:

```powershell
go build -o bin/snablr.exe ./cmd/snablr
.\bin\snablr.exe --help
```

Note:
- `make build` injects version, commit, and build date metadata.
- Plain `go build` is fine for development, but will usually show `dev` / `unknown` metadata unless you pass ldflags yourself.

Minimum source-build verification:

```bash
go build ./...
make build
./bin/snablr version
```

## Quick Start

### 1. Download A Release Or Build From Source

Use either:

- a release archive from GitHub Releases
- `make build` if you are building locally

### 2. Verify The Binary Works

If `snablr` is not installed on your `PATH`, use `./bin/snablr` instead.

```bash
snablr version
```

Or, if you are running from the repo:

```bash
./bin/snablr version
```

### 3. Run A Simple Direct-Host Scan

Use this when you already know the host you want to review.

You need:

- one reachable Windows host with SMB enabled
- a username and password that can authenticate to that host

```bash
snablr scan --targets 10.0.0.5 --user USER --pass PASS --output-format all --json-out results.json --html-out report.html
```

What this does:

1. loads config defaults and rule packs
2. uses the explicit target instead of LDAP discovery
3. checks SMB reachability unless disabled
4. enumerates accessible shares
5. scans matching files with the active rule set
6. writes findings to console, JSON, and HTML

Live console note:

- scans that require LDAP/DFS credentials now run a credential preflight before the TUI starts
- invalid required credentials abort the scan immediately and the TUI is not launched
- discovery-based scans now show target discovery and reachability progress in plain console output before the TUI opens
- the interactive TUI starts only after startup work completes and real target counts are available
- interactive terminal scans now open a two-pane TUI
- the left pane shows finding metadata, scan progress, and current activity
- the right pane shows evidence and detail for the currently selected finding
- evidence is intentionally kept out of the left pane so raw secrets do not scroll by in the live finding list
- default live output is filtered to primary findings only; weaker supporting artifacts remain available for correlation and in exported reports
- the HTML report keeps the full dataset, but opens with config-only and non-actionable findings hidden by default
- each scan also writes `scanned_targets.txt` by default so discovery-mode runs leave an audit trail of reachable and actually scanned targets
- report/export flags such as `--output-format html`, `--output-format html,json`, `--json-out`, `--html-out`, and sidecar exports do not disable the TUI
- the TUI is the default live interface for interactive runs; exports are additional outputs
- pass `--no-tui` if you want the old plain stdout console output in an interactive terminal

Archive note:

- `.zip` files up to 10 MB are inspected by default
- only text-like members are inspected
- nested archives are skipped
- archive member findings are reported as `outer.zip!inner/path`
- archive-contained private keys and client-auth artifacts use the same `outer.zip!inner/path` format and keep their inner member context in JSON and HTML output
- remote SMB scans fetch the outer archive and inspect it locally in the Snablr process; archives are not unpacked on the target

SQLite note:

- `.sqlite`, `.sqlite3`, `.db`, and `.db3` files can be inspected locally when they fall within the configured SQLite size limits
- Snablr validates the SQLite header before inspection
- inspection is read-only and bounded by table, row, cell, and total-byte limits
- findings use a combined path like `app.db::users.password`
- JSON and HTML output also preserve `database_file_path`, `database_table`, `database_column`, and `database_row_context`
- remote SMB scans read the outer SQLite file and inspect it locally in the Snablr process; databases are never queried on the remote target

Backup exposure note:

- exact backup path families such as `WindowsImageBackup`, `System Volume Information`, `RegBack`, and `Windows/repair` are detected as high-signal backup-exposure artifacts
- grouped backup contexts containing multiple hive or AD database artifacts can be promoted into an access-path summary for faster operator triage

Browser credential-store note:

- exact Firefox profile artifacts such as `logins.json` and `key4.db` are detected by exact profile path and filename
- exact Chromium-family profile artifacts such as `Login Data` and `Cookies` are detected by exact profile path and filename
- standalone browser credential-store artifacts stay low-visibility until paired exact profile artifacts are found in the same normalized browser profile context

Top access-path note:

- correlated findings are grouped into deterministic access-path types such as AD compromise path, VPN/client-auth access path, Windows credential-store exposure, database access path, and archive-derived credential cluster
- the report ranks these clusters by exploitability score and priority tier so operators can act on the highest-value paths first
- the raw findings remain available below the summary, so every ranked cluster stays traceable to the original evidence

Suppression note:

- explicit suppression rules can hide known-benign findings by exact path, path subtree, rule ID, fingerprint, host/share scope, tag, or known application path context
- suppressed findings are summarized separately in JSON, HTML, and console output so they remain auditable
- suppression is applied before correlated access-path summaries are generated

### 4. Open The HTML Report

The HTML report is written to the path you supplied with `--html-out`.

In the example above:

- JSON results go to `results.json`
- HTML report goes to `report.html`

Open `report.html` in a browser after the scan completes.

If you are running from the repo root and the binary is not on `PATH`, use:

```bash
./bin/snablr scan --targets 10.0.0.5 --user USER --pass PASS --output-format all --json-out results.json --html-out report.html
```

### 5. Try A Domain-Aware Scan

Use this when you want Snablr to discover targets from LDAP automatically.

You need:

- LDAP connectivity to a domain controller
- credentials that work for LDAP and SMB

```bash
snablr scan --user USER --pass PASS --output-format all --json-out results.json --html-out report.html
```

LDAP discovery is used only when you do not provide `--targets` or `--targets-file`.

## When To Use What

- Direct target scan
  Use when you already know the file server or small host list you want to review.
- Domain-aware scan
  Use when you want Snablr to discover likely targets from LDAP automatically.
- `rules test`
  Use before a live scan when you want to verify a rule against a known file.
- `diff`
  Use after repeated scans when you want to focus on what changed since the last run.

## Output Formats

Snablr supports these primary output modes:

- `console`
  Prints findings directly to the terminal.
- `json`
  Writes one machine-readable JSON report to `--json-out`.
- `html`
  Writes one standalone HTML report to `--html-out`.
- `all`
  Writes console output and both JSON and HTML reports.

Optional sidecar exports:

- `--csv-out`
- `--md-out`
- `--creds-out`

If you do not provide output paths, the defaults from your config file are used. If you override them on the CLI, Snablr writes to the paths you provide.

## Lab Seeder

Snablr also includes `snablr-seed`, a lab-only helper for generating synthetic fake SMB share content so you can test scans, prioritization, reporting, and manifest-to-results verification end to end.

Quick start:

```bash
go build -o bin/snablr-seed ./cmd/snablr-seed

./bin/snablr-seed \
  --targets 172.16.0.90 \
  --user USER \
  --pass PASS \
  --count-per-category 25 \
  --max-files 500 \
  --manifest-out seed-manifest.json
```

Verification workflow:

```bash
./bin/snablr scan --targets 172.16.0.90 --user USER --pass PASS --json-out results.json
./bin/snablr-seed verify --manifest seed-manifest.json --results results.json
```

Important notes:

- `snablr-seed` generates only synthetic fake data for authorized lab use.
- Administrative shares are excluded by default unless explicitly requested.
- `make build` builds `snablr`; build `snablr-seed` separately with `go build`.
- Full seeder usage, safety constraints, scaling flags, and verification details are in `docs/seeder.md`.

## First-Time User Tip

If you are unsure where to start:

1. build with `make build`
2. run `./bin/snablr version`
3. run one direct target scan with `--output-format all`
4. open the generated `report.html`
5. only then move on to LDAP discovery, custom rules, and diff mode

## Common Workflows

### Scan A Single Host

```bash
snablr scan \
  --targets 10.0.0.5 \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --output-format console
```

### Use A Config File

```bash
snablr scan --config examples/config.basic.yaml
```

### Let LDAP Discover Targets

If `targets` and `targets_file` are empty, Snablr tries to detect domain context and discover computers through LDAP unless `--no-ldap` is set.

```bash
snablr scan \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --output-format console
```

### Restrict Scan Scope

```bash
snablr scan \
  --config examples/config.targeted.yaml \
  --share Finance \
  --path Payroll/ \
  --max-depth 4
```

### Compare Against A Baseline

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --baseline previous-results.json \
  --output-format all \
  --json-out results.json \
  --html-out report.html
```

Or compare two existing JSON reports directly:

```bash
snablr diff --old previous-results.json --new results.json
```

### Seed, Scan, And Verify

Use this when you want an end-to-end lab validation loop with synthetic content.

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --user USER \
  --pass PASS \
  --seed-prefix SnablrLab \
  --manifest-out seed-manifest.json

snablr scan \
  --targets 172.16.0.90 \
  --user USER \
  --pass PASS \
  --path SnablrLab \
  --seed-manifest seed-manifest.json \
  --output-format all \
  --json-out results.json \
  --html-out report.html

snablr-seed verify --manifest seed-manifest.json --results results.json
```

## How LDAP Discovery Works

When no manual targets are supplied, Snablr can:

1. detect the domain from environment variables, hostname data, or resolver configuration
2. find a domain controller through DNS SRV lookups
3. query LDAP RootDSE for the default naming context
4. attempt LDAP simple bind with the configured credentials
5. automatically retry over LDAPS if the server requires stronger authentication or signing
6. enumerate computer objects from that base DN
7. merge and deduplicate those discovered hosts into the normal target pipeline

You can override discovery with:

- `--no-ldap`
- `--domain`
- `--dc`
- `--base-dn`

See:
- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)

## How SMB Scanning Works

Once Snablr has a target list, it:

1. optionally checks TCP `445` reachability
2. plans host/share/file order so high-value targets go first
3. authenticates to SMB using the provided credentials
4. enumerates accessible shares and share metadata
5. walks files and directories with scope filters applied early
6. loads file content only when content rules actually need it
7. records findings, metrics, and optional checkpoints

This separation matters:

- discovery finds likely targets
- SMB handles transport and file access
- scanner applies rules
- output turns findings into reports

## Rule System Overview

Rules are stored as editable YAML files under:

- `configs/rules/default/`
- `configs/rules/custom/`

They support:

- `content`, `filename`, and `extension` rule types
- severity, tags, category, confidence, explanation, and remediation fields
- path include/exclude filters
- extension filters
- runtime enable/disable without recompiling

Validate and test rules with:

```bash
snablr rules validate --config configs/config.yaml
snablr rules test --rule configs/rules/default/content.yml --input testdata/rules/fixtures/content/password-assignment.conf --verbose
snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose
```

See:
- [Rules](docs/rules.md)
- [Rule Tuning](docs/tuning.md)

## HTML Report Usage

The HTML report is the main post-scan triage artifact. It is standalone and does not require external assets.

What to look at first:

1. summary cards
   Hosts scanned, shares scanned, files scanned, matches, skipped files, read errors, and scan duration
2. severity summary
   Helps you decide whether to start with critical/high findings or broad category review
3. category summary
   Shows where the bulk of findings live
4. grouped findings
   Findings are grouped by category, then ordered by severity for practical review
5. seeded validation summary, when `--seed-manifest` is provided
   Shows expected versus observed behavior for seeded lab content

How to interpret a finding row:

- severity and confidence badges show urgency and likely signal quality
- host/share/file path identify where the finding came from
- source badges highlight LDAP, DFS, SYSVOL, NETLOGON, and planner priority context
- confidence breakdown explains content strength, value quality, correlation, and path/context contribution
- match snippet shows the evidence that triggered the rule
- rule explanation tells you why the rule exists
- remediation guidance helps you turn the finding into defensive follow-up

The HTML report also includes structured client-side filters that work together with the quick text search. Operators can filter by severity, category, confidence, source, host/share, signal type, correlated findings, actionable evidence, and low-value config-only findings.

There is no screenshot committed yet, so the report sections above are described directly in the docs.

See:
- [Reporting](docs/reporting.md)

## Examples

The [`examples`](examples) directory includes:

- [`config.basic.yaml`](examples/config.basic.yaml)
- [`config.domain.yaml`](examples/config.domain.yaml)
- [`config.targeted.yaml`](examples/config.targeted.yaml)
- [`rules/custom/example.yml`](examples/rules/custom/example.yml)
- [`commands.md`](examples/commands.md)

## Additional Documentation

- [Build And Release](docs/building.md)
- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Reporting](docs/reporting.md)
- [Architecture](docs/architecture.md)
- [Workflows](docs/workflows.md)
- [Validation Report](docs/validation-report.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Security Policy](SECURITY.md)

## Development

Useful targets:

```bash
make build
make test
make lint
make release-snapshot VERSION=v1.0.0
```

`make release` is an alias to `make release-snapshot`.

The release snapshot and GitHub release workflow build:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

## License

This repository is licensed under the terms of the [GNU GPLv3](LICENSE).
