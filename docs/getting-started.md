# Getting Started

Snablr is a Go-based SMB share triage tool for defensive review of Windows file shares. It discovers scan targets, enumerates accessible shares, walks files, applies YAML-driven rules, and writes findings in several formats for remediation and review.

This guide covers the shortest path from a clone of the repository to a first successful scan.

## What Snablr Does

At a high level, Snablr:

1. loads configuration and rule packs
2. discovers or accepts scan targets
3. checks SMB reachability
4. prioritizes hosts, shares, and files
5. walks shares and scans matching files
6. writes console, JSON, HTML, CSV, or Markdown output

The project is intended for defensive use cases such as:

- share hygiene review
- detection tuning
- identifying exposed sensitive configuration or export material
- producing remediation-oriented review artifacts

## Prerequisites

- Go `1.22+`
- network access to target SMB hosts on TCP `445`
- valid credentials for the target environment

If you want Snablr to discover targets from Active Directory automatically, you also need LDAP connectivity to a domain controller.

## Build Snablr

### Using Make

```bash
make build
```

This builds the binary into `bin/snablr`.

### Using Go Directly

```bash
go build -o bin/snablr ./cmd/snablr
```

### Verify the Build

```bash
./bin/snablr version
./bin/snablr --help
```

## First Scan: Direct Host

The simplest first run is a direct scan against one host:

```bash
./bin/snablr scan \
  --targets 172.16.0.90 \
  --user 'DOMAIN\user' \
  --pass 'REPLACE_ME' \
  --output-format console
```

Expected behavior:

- the banner prints
- rules are loaded and validated
- the host is checked for SMB reachability
- accessible shares are enumerated
- files are scanned according to the active rule pack
- findings print to the console if matches are found

## First Scan: Config-Driven

For a more repeatable workflow, use one of the example configs:

```bash
./bin/snablr scan --config examples/config.basic.yaml
```

The basic example shows:

- a direct target list
- placeholder credentials
- adaptive worker scaling
- combined JSON and HTML output

## First Scan: Domain-Aware

If you want Snablr to discover targets from Active Directory, leave explicit targets empty and provide credentials:

```bash
./bin/snablr scan \
  --user 'DOMAIN\user' \
  --pass 'REPLACE_ME' \
  --output-format console
```

Or use the example domain-aware config:

```bash
./bin/snablr scan --config examples/config.domain.yaml
```

Expected behavior:

- Snablr attempts to determine domain context
- LDAP discovery loads likely computer targets
- SMB reachability checks reduce wasted connection attempts
- high-value shares are prioritized before lower-value ones

## First Scan: Targeted Triage

If you want to validate a specific share or path quickly:

```bash
./bin/snablr scan \
  --targets fs01.example.local \
  --user 'DOMAIN\user' \
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

## Expected Outputs

Snablr supports several output modes.

### Console

Best for live operator feedback.

Example:

```text
[HIGH] content.password_assignment_indicators
Host: FS01
Share: Finance
File: \\FS01\Finance\web.config
Rule: Password Assignment Indicators
Category: credentials
Match: password=Secret123
```

### JSON

Best for automation, post-processing, and downstream tooling.

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --output-format json \
  --json-out results.json
```

### HTML

Best for post-scan review in a browser.

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --output-format html \
  --html-out report.html
```

### Combined Output

Recommended for most real scans:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/results.json \
  --html-out output/report.html \
  --csv-out output/findings.csv \
  --md-out output/summary.md
```

## Next Steps

After your first scan:

1. validate and review the active rule pack
2. add organization-specific rules under a custom rules directory
3. test those rules against fixtures before using them live
4. use checkpoints for larger scans
5. review the HTML report for grouped triage

Related docs:

- `docs/configuration.md`
- `docs/rules.md`
- `docs/reporting.md`
- `docs/workflows.md`
- `docs/troubleshooting.md`
