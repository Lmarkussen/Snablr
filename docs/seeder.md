# Snablr Seeder

## Purpose

`snablr-seed` is a lab-only helper that writes synthetic fake files into SMB shares so Snablr can be validated end-to-end.

It is designed to help test:

- rule coverage
- planner prioritization
- HTML and JSON reporting
- diff mode
- manifest-to-finding comparison workflows

## Safety Constraints

The seeder is intentionally defensive and non-weaponized.

- It generates only obviously fake data.
- It does not use real secrets.
- It does not embed real credentials in source code.
- SMB targets and credentials must come from CLI flags.
- Cleanup is limited to the configured seed prefix only.

Examples of generated fake values:

- `EXAMPLE_PASSWORD_001`
- `FAKE_API_KEY_ABC123`
- `DEMO_CONN_STRING`
- `NOT_A_REAL_SECRET`

## Supported Formats

The default templates generate a range of realistic-looking placeholder files, including:

- `txt`
- `ini`
- `conf`
- `cfg`
- `xml`
- `json`
- `yaml`
- `yml`
- `csv`
- `log`
- `ps1`
- `bat`
- `cmd`
- `sh`
- `sql`
- `env`
- `properties`
- `md`
- `docx`
- `xlsx`
- `pem`
- `key`
- `crt`
- `pfx`

`docx`, `xlsx`, and `pfx` outputs are placeholder text files with realistic names, not true binary Office or certificate archive files.

## Template Categories

The default template pack covers these synthetic categories:

- `config`
- `script`
- `backup`
- `database`
- `web`
- `hr`
- `finance`
- `payroll`
- `archive`
- `cloud`
- `keys`
- `logs`
- `deployment`
- `vpn`
- `keepass`
- `customer_export`

Each category includes multiple filename variants, directory placements, and content layouts so scans exercise more than one naming or content pattern.

## Rule Theme Coverage

Each generated file records expected tags and expected rule themes in the manifest.

Examples of rule themes exercised by the default templates:

- hardcoded secret indicators
- config file review
- script credential review
- database connection string detection
- backup and export naming review
- cloud configuration exposure
- API token exposure
- private key and certificate material review
- unattended install and deployment config review
- VPN config review
- KeePass and password-manager artifact review
- PII and business-sensitive filename review
- HR, finance, payroll, and customer export review
- log review

## Directory Layout

Files are written under a controlled prefix, for example:

- `SnablrLab/IT/`
- `SnablrLab/IT/Admin/`
- `SnablrLab/IT/Scripts/`
- `SnablrLab/Finance/`
- `SnablrLab/HR/`
- `SnablrLab/Payroll/`
- `SnablrLab/Backups/`
- `SnablrLab/Config/`
- `SnablrLab/Deploy/`
- `SnablrLab/SQL/`
- `SnablrLab/Web/`
- `SnablrLab/Users/Alice/`
- `SnablrLab/Users/Bob/`
- `SnablrLab/Archive/`
- `SnablrLab/Old/`
- `SnablrLab/Temp/`

## Example Commands

Dry-run only:

```bash
snablr-seed --targets fs01 --username 'DOMAIN\\user' --password 'PLACEHOLDER' --dry-run
```

Seed multiple hosts and write a manifest:

```bash
snablr-seed \
  --targets fs01,fs02 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --manifest-out seed-manifest.json
```

Restrict to one share:

```bash
snablr-seed \
  --targets fs01 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --share Finance
```

Clean only the existing seeded prefix before reseeding:

```bash
snablr-seed \
  --targets fs01 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --seed-prefix SnablrLab \
  --clean-prefix
```

Deterministic generation:

```bash
snablr-seed \
  --targets fs01 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --random-seed 20260315
```

Verification against a Snablr scan result:

```bash
snablr-seed verify --manifest seed-manifest.json --results results.json
```

## Cleanup Behavior

Cleanup is intentionally limited.

- `--clean-prefix` removes only the configured `--seed-prefix`
- it will not delete outside that prefix
- empty or traversal-style prefixes are rejected

Example:

```bash
snablr-seed --targets fs01 --username 'DOMAIN\\user' --password 'PLACEHOLDER' --seed-prefix SnablrLab --clean-prefix
```

This removes only `SnablrLab/` under the selected shares before writing new files.

## Manifest Output

The manifest is JSON and records where each seeded file was placed.

Each entry includes:

- host
- share
- path
- category
- format
- expected tags
- expected rule themes
- expected severity
- status

This makes it easier to compare seeding intent with Snablr findings.

## Compare Manifest Entries With Findings

Typical workflow:

1. Seed the lab shares with `snablr-seed`
2. Run `snablr scan` against the same hosts
3. Review the HTML and JSON reports
4. Compare finding paths, categories, tags, and rule themes to the seeder manifest
5. Tune rules or exclusions where expected files were missed or noisy rules overmatched

The seeder manifest is useful as a lightweight expected-results reference when validating rule packs, diff behavior, and reporting.

## Verification Mode

`snablr-seed verify` compares:

- the seeder manifest
- a Snablr JSON scan result

It reports:

- expected items found
- expected items missed
- unexpected findings
- category coverage

The comparison is intentionally simple and explainable:

- manifest entries are matched to findings by normalized `host + share + path`
- a seeded item counts as found if at least one finding matches that seeded path
- a finding is unexpected if it does not map back to any manifest entry
