# Snablr Seeder

## Purpose

`snablr-seed` is a lab-only helper that writes synthetic fake files into SMB shares so Snablr can be validated end-to-end at larger scale.

It is intended to exercise:

- rule coverage across many categories and file formats
- planner prioritization across noisy and high-value paths
- HTML, JSON, CSV, Markdown, and console reporting
- diff mode
- manifest-to-finding verification workflows

## Safety Constraints

The seeder is intentionally defensive and non-weaponized.

- It generates only synthetic fake data.
- It uses obviously fake values only.
- It does not embed real credentials in source code.
- SMB targets and credentials must come from CLI flags.
- Cleanup is limited to the configured seed prefix only.

Examples of generated fake values:

- `EXAMPLE_PASSWORD_001_1234`
- `FAKE_API_KEY_ABC123`
- `TEST_ONLY_TOKEN_XYZ`
- `NOT_A_REAL_SECRET`
- `DEMO_CONN_STRING`

## Scale And Determinism

The seeder can now generate hundreds or thousands of files.

Useful scaling flags:

- `--count-per-category`
  Number of files to generate for each synthetic category
- `--max-files`
  Hard cap on total generated files
- `--depth`
  Extra nested directory depth to add under each base path
- `--random-seed`
  Deterministic seed for reproducible file/content variation
- `--shares-per-target`
  Limit how many shares are seeded on each target
- `--likely-hit-ratio`
  Bias generation toward likely-hit files versus filler/noise
- `--filename-only-ratio`
  Bias generation toward filename/path-style hits instead of content hits
- `--high-severity-ratio`
  Bias generation toward high-severity synthetic content
- `--medium-severity-ratio`
  Bias generation toward medium-severity synthetic content

Generation remains deterministic when you reuse the same:

- targets
- share selection
- count/depth/max settings
- random seed

## Lab Targets

Example lab hosts:

- `DC01` at `172.16.0.80`
- `FS01` at `172.16.0.90`

The seeder does not hardcode these values. They are just realistic example targets for lab use.

## Personas

The generated dataset uses synthetic usernames for realism only:

- `alice`
- `bob`
- `charlie`
- `david`
- `svc_backup`
- `svc_sql`
- `svc_deploy`
- `snaffleuser`

## Categories

The default synthetic catalog currently includes these generation categories:

- `configs`
- `deploy`
- `vpn`
- `keepass`
- `finance`
- `sql`
- `zip-archives`
- `cloud`
- `legacy`
- `user-notes`
- `scripts`
- `temp`
- `backups`
- `service-accounts`
- `noise`

Across those categories, the file names and content cover common enterprise areas such as web configs, exports, payroll-style data, service-account notes, legacy archives, deployment answers, cloud placeholders, zip-based honeypots, and benign clutter.

## Filename Patterns

The filename library now includes many more realistic enterprise-style names, including:

- `passwords.txt`
- `creds-old.txt`
- `notes-old-creds.txt`
- `db-backup.conf`
- `web.config`
- `appsettings.json`
- `deploy.env`
- `vpn-config.txt`
- `keepass-export.csv`
- `payroll-export-2025.csv`
- `customer_export_q1.csv`
- `service-account-notes.txt`
- `backup-script.ps1`
- `unattended.xml`
- `install-answer.ini`
- `finance-share-notes.txt`
- `sql-connection.properties`
- `azure-config.yaml`
- `aws-migration-notes.txt`
- `legacy-app.conf`
- `prod-config-old.yml`
- `scripts-readme.md`
- `temp-secrets.log`
- `archive-notes.txt`
- `deploy-package.zip`
- `legacy-configs.zip`
- `deployment-recovery.zip`
- `old-config-bundle.zip`
- `binary-media-bundle.zip`
- `nested-export-bundle.zip`
- `oversized-config-export.zip`

The generator also adds benign clutter such as:

- `meeting-notes.md`
- `readme.txt`
- `inventory.csv`
- `changelog.txt`
- `team-contacts.csv`
- `project-plan.md`
- `app-log.log`
- `deployment-notes.txt`

## Formats

The default catalog generates realistic-looking placeholders across:

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
- `cmd`
- `sh`
- `env`
- `properties`
- `md`
- `zip`

`zip` honeypots are generated programmatically and currently cover:

- small text-heavy archives that should be inspected by default
- config-only archives that should stay low-value
- nested-archive negative cases
- binary-only negative cases
- oversized archives that should be skipped unless larger archive inspection is enabled

## Fake Content Patterns

Generated content now varies across several realistic but safe styles:

- `key=value`
- `key: value`
- XML elements
- JSON fields
- YAML mappings
- shell `export` statements
- PowerShell variables
- CSV rows
- freeform notes text
- readme/changelog/project-note filler

Safe fake values include:

- `EXAMPLE_PASSWORD_001`
- `EXAMPLE_PASSWORD_002`
- `NOT_A_REAL_SECRET`
- `DEMO_CONN_STRING`
- `TEST_ONLY_TOKEN_XYZ`
- `FAKE_API_KEY_ABC123`
- `SAMPLE_CLIENT_SECRET_001`
- `LAB_ONLY_VALUE_DO_NOT_USE`

## Directory Layout

Files are written under a controlled prefix, for example `SnablrLab/`.

The default path layout intentionally resembles a larger file-share environment:

- `SnablrLab/IT/`
- `SnablrLab/IT/Admin/`
- `SnablrLab/IT/Scripts/`
- `SnablrLab/IT/Deploy/`
- `SnablrLab/Finance/`
- `SnablrLab/Finance/Exports/`
- `SnablrLab/HR/`
- `SnablrLab/HR/Payroll/`
- `SnablrLab/SQL/`
- `SnablrLab/SQL/Backups/`
- `SnablrLab/Web/`
- `SnablrLab/Web/Configs/`
- `SnablrLab/Users/Alice/Desktop/`
- `SnablrLab/Users/Bob/Documents/`
- `SnablrLab/Users/Charlie/Downloads/`
- `SnablrLab/Users/David/Desktop/`
- `SnablrLab/Archive/Legacy/App1/Config/`
- `SnablrLab/Archive/Legacy/App2/Config/`
- `SnablrLab/Backups/Daily/`
- `SnablrLab/Backups/Monthly/`
- `SnablrLab/Old/`
- `SnablrLab/Temp/`
- `SnablrLab/Customer Data/`

`--depth` adds more nested segments under those base directories so scans can exercise deeper path traversal and prioritization.

## Manifest Metadata

Each seeded file is written to the manifest with expected metadata for later verification.

Each manifest entry includes:

- host
- share
- path
- category
- format
- intended-as classification
- expected triage class
- expected confidence
- expected correlated state
- expected signal types
- expected tags
- expected rule themes
- expected severity
- write status

This makes the manifest useful as a lightweight expected-results dataset for rule and reporting validation.

## Verification Mode

`snablr-seed verify` compares:

- the seeder manifest
- a Snablr JSON scan result

Matching remains simple and explainable:

- manifest entries are matched to findings by normalized `host + share + path`
- a seeded item counts as found if at least one finding matches that path
- a finding is unexpected if it does not map back to any manifest entry

Verification summarizes:

- total expected items
- found items
- missed items
- unexpected findings
- coverage by category
- coverage by signal type
- seeded class behavior across:
  - informational / config-only
  - weak review
  - actionable
  - correlated / high-confidence

It also calls out:

- config-only items that were safely suppressed or downgraded
- actionable items that were promoted correctly
- correlated high-confidence items that surfaced as intended
- class mismatches where a seeded item was missed, under-promoted, or surfaced too weakly

Signal-type coverage uses the manifest’s expected signal types and checks whether the findings for that seeded path actually hit those surfaces.

## Example Commands

Generate a small dataset:

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --count-per-category 2 \
  --max-files 80 \
  --depth 1 \
  --manifest-out seed-small.json
```

Generate a large dataset:

```bash
snablr-seed \
  --targets 172.16.0.80,172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --count-per-category 24 \
  --max-files 1200 \
  --depth 3 \
  --shares-per-target 2 \
  --random-seed 20260316 \
  --manifest-out seed-large.json
```

Generate a more noisy dataset:

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --count-per-category 18 \
  --max-files 900 \
  --likely-hit-ratio 35 \
  --filename-only-ratio 20 \
  --high-severity-ratio 20 \
  --medium-severity-ratio 35 \
  --depth 2
```

Generate a higher-signal dataset:

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --count-per-category 18 \
  --max-files 900 \
  --likely-hit-ratio 85 \
  --filename-only-ratio 45 \
  --high-severity-ratio 60 \
  --medium-severity-ratio 25 \
  --depth 2
```

Target a single share only:

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --share Finance \
  --count-per-category 10 \
  --max-files 200
```

Dry run only:

```bash
snablr-seed \
  --targets 172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --count-per-category 12 \
  --max-files 400 \
  --dry-run
```

Clean only the seed prefix before reseeding:

```bash
snablr-seed \
  --targets 172.16.0.80,172.16.0.90 \
  --username 'DOMAIN\\user' \
  --password 'PLACEHOLDER' \
  --seed-prefix SnablrLab \
  --clean-prefix
```

Verify coverage after a scan:

```bash
snablr-seed verify \
  --manifest seed-large.json \
  --results results.json
```

## Cleanup Behavior

Cleanup is intentionally narrow.

- `--clean-prefix` removes only the configured `--seed-prefix`
- it will not delete outside that prefix
- empty or traversal-style prefixes are rejected

That keeps cleanup safe even when seeding multiple hosts and shares.

## Suggested Workflow

1. Generate a deterministic dataset with `snablr-seed`
2. Run `snablr scan` against the same targets and shares
3. Pass `--seed-manifest` during the scan so the HTML and JSON reports include the seeded validation summary directly
4. Review the HTML and JSON reports for triage quality
5. Run `snablr-seed verify` against the scan results for the full console-oriented verifier output
6. Tune rules, planning, and reporting based on misses or unexpected findings

Recommended scan pattern:

```bash
snablr scan \
  --targets 172.16.0.90 \
  --user 'DOMAIN\\user' \
  --pass 'PLACEHOLDER' \
  --path SnablrLab \
  --seed-manifest seed-large.json \
  --output-format all \
  --json-out results.json \
  --html-out report.html
```

Using `--path` with the seed prefix keeps seeded regression runs isolated from older lab content on the same server.

## Notes

- The seeder produces realistic-looking fake enterprise data only.
- It is suitable for labs, demos, verification, and regression testing.
- It is not intended to simulate or carry real credentials or sensitive business data.
