# Configuration

Snablr can be configured with:

- built-in defaults
- a YAML config file
- CLI flags

The default runtime config file is:

- `configs/config.yaml`

Example profiles live under:

- `examples/config.basic.yaml`
- `examples/config.domain.yaml`
- `examples/config.targeted.yaml`
- `examples/config.production.yaml`

## Configuration Precedence

Snablr applies configuration in this order:

1. built-in defaults
2. YAML config file
3. CLI flags

CLI flags always win for the current run.

Example:

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --share SYSVOL \
  --max-scan-time 30m
```

In that example:

- the YAML file provides the base config
- `--share` overrides the configured share list
- `--max-scan-time` overrides the configured time limit

## Top-Level Sections

The config file is grouped into:

- `app`
- `scan`
- `archives`
- `sqlite`
- `suppression`
- `rules`
- `output`

## `app`

Example:

```yaml
app:
  name: snablr
  log_level: info
  banner_path: internal/ui/assets/snablr.txt
```

Fields:

- `name`
  Display name used by the application. This should normally remain `snablr`.
- `log_level`
  Logging verbosity. Typical values are `debug`, `info`, `warn`, `error`.
- `banner_path`
  Runtime path to the ASCII banner asset.

## `scan`

The `scan` section controls target selection, discovery, scope filtering, performance, and runtime behavior.

### Targets

- `targets`
  Explicit list of hosts to scan.
- `targets_file`
  Path to a file containing one target per line.

Behavior:

- if `targets` or `targets_file` is set, Snablr uses those targets
- if both are empty, Snablr attempts LDAP discovery unless disabled

### Credentials

- `username`
  SMB and LDAP username
- `password`
  SMB and LDAP password

Committed configs should use placeholders, not real secrets.

Typical override pattern:

```bash
snablr scan --config examples/config.domain.yaml --user 'DOMAIN\user' --pass 'REPLACE_ME'
```

### LDAP Discovery

- `no_ldap`
  Disable LDAP discovery
- `domain`
  Manual domain override
- `dc`
  Manual domain controller override
- `base_dn`
  Manual LDAP search base override
- `discover_dfs`
  Enable DFS discovery so linked shares can be added to the pipeline

How LDAP discovery works:

1. Snablr checks for explicit targets
2. if none are present, it tries to detect domain context
3. it finds a domain controller or uses `dc`
4. it attempts LDAP simple bind with the configured credentials
5. if the server requires stronger authentication or signing, it retries over LDAPS automatically
6. it queries LDAP for computer objects
7. it merges those discovered hosts into the target pipeline

Notes:

- the automatic fallback is transport-level only; it does not currently switch to Kerberos bind automatically
- logs indicate which LDAP method was used so discovery behavior stays transparent during troubleshooting

### Share And Path Filters

- `share`
  Only scan these share names
- `exclude_share`
  Skip these share names
- `path`
  Only scan files under these share-relative path prefixes
- `exclude_path`
  Skip files under these path prefixes
- `max_depth`
  Maximum recursion depth during share walking

These filters are applied early during share selection and file walking so they reduce work before file scanning starts.

### Reachability

- `skip_reachability_check`
  Skip TCP `445` reachability testing
- `reachability_timeout_seconds`
  Timeout for SMB reachability checks

Recommended default:
- keep reachability enabled for larger scans to reduce wasted SMB connection attempts

### Planning

- `prioritize_ad_shares`
  Give extra planning priority to `SYSVOL` and `NETLOGON`
- `only_ad_shares`
  Restrict scanning to `SYSVOL` and `NETLOGON`

### Performance

- `worker_count`
  Number of file scanning workers

Special behavior:
- `0` means adaptive worker scaling

- `max_file_size`
  Maximum file size Snablr will consider for scanning

Larger values increase coverage but also increase I/O and memory pressure.

### Runtime Control

- `profile`
  Explicit scan profile. Supported values are `default`, `validation`, and `aggressive`.

- `baseline`
  Path to a previous JSON result used for comparison during the current scan
- `seed_manifest`
  Path to a seeder manifest JSON file so the report can include seeded expected-versus-observed validation
- `validation_mode`
  Enable extra diagnostic tracking for skipped files, suppressed findings, downgraded findings, and validation metrics
- `max_scan_time`
  Maximum total scan time, for example `30m` or `2h`
- `checkpoint_file`
  Path to the checkpoint JSON file
- `resume`
  Resume from a previous checkpoint

Resume behavior:

- file completion is keyed by path plus file metadata
- resumed scans reprocess files whose size or modified timestamp changed
- this avoids the earlier path-only skip behavior for changed files without adding heavy content hashing by default

### Scan Profiles

Profiles set predictable bounded-inspection behavior without requiring many ad hoc flags.

- `default`
  Balanced production profile. Recommended for everyday live-environment scans.
- `validation`
  Conservative review-oriented profile. Uses tighter archive and SQLite limits and enables validation diagnostics.
- `aggressive`
  Broader bounded-inspection profile. Still local-side and bounded, but allows larger archive and SQLite inspection limits.

Profile notes:

- profiles only tune existing bounded-inspection and diagnostics settings
- they do not add new detection families
- CLI flags still override the active profile for the current run
- the selected profile is recorded in console, JSON, and HTML output

## `archives`

The `archives` section controls limited archive inspection.

Phase 1 support is intentionally narrow:

- `.zip`
- `.tar`
- `.tar.gz`
- `.tgz`
- local in-process inspection using Go stdlib
- no nested archive traversal
- no password-protected archive support
- no extraction to disk during normal scanning

Example:

```yaml
archives:
  enabled: true
  auto_zip_max_size: 10485760
  allow_large_zips: false
  max_zip_size: 10485760
  auto_tar_max_size: 10485760
  allow_large_tars: false
  max_tar_size: 10485760
  max_members: 64
  max_member_bytes: 524288
  max_total_uncompressed_bytes: 4194304
  inspect_extensionless_text: true
```

Fields:

- `enabled`
  Enable limited `.zip` inspection.
- `auto_zip_max_size`
  Automatically inspect `.zip` files up to this size in bytes. Default: `10485760` (10 MB).
- `allow_large_zips`
  Permit `.zip` inspection above the automatic limit when `max_zip_size` allows it.
- `max_zip_size`
  Absolute maximum `.zip` size Snablr will inspect when large-zip inspection is enabled.
- `auto_tar_max_size`
  Automatically inspect `.tar`, `.tar.gz`, and `.tgz` files up to this size in bytes. Default: `10485760` (10 MB).
- `allow_large_tars`
  Permit tar-based archive inspection above the automatic limit when `max_tar_size` allows it.
- `max_tar_size`
  Absolute maximum tar-based archive size Snablr will inspect when larger tar inspection is enabled.
- `max_members`
  Maximum number of archive members inspected per supported archive.
- `max_member_bytes`
  Maximum uncompressed bytes read from any single member.
- `max_total_uncompressed_bytes`
  Maximum total uncompressed bytes read across inspected members in one archive.
- `inspect_extensionless_text`
  Inspect extensionless members when they look text-like.

Behavior:

- `.zip` files above the automatic limit are skipped by default
- tar-based archives above the automatic limit are skipped by default
- `.rar`, `.7z`, and similar formats remain skipped by default
- only text-like members are inspected
- nested archives are skipped
- remote scans never unpack archives on the target side; the outer file is read and inspected locally
- archive findings are reported with both the outer archive path and inner member path

## `sqlite`

The `sqlite` section controls limited offline SQLite inspection.

Phase 1 support is intentionally narrow:

- `.sqlite`, `.sqlite3`, `.db`, and `.db3` candidates only
- SQLite header validation before inspection
- local read-only inspection only
- bounded schema and row sampling
- no live DB access
- no full-database dumping

Example:

```yaml
sqlite:
  enabled: true
  auto_db_max_size: 5242880
  allow_large_dbs: false
  max_db_size: 5242880
  max_tables: 8
  max_rows_per_table: 5
  max_cell_bytes: 256
  max_total_bytes: 16384
  max_interesting_columns: 4
```

Fields:

- `enabled`
  Turn SQLite inspection on or off.
- `auto_db_max_size`
  SQLite files at or below this size are inspected automatically.
- `allow_large_dbs`
  Allow inspection above the automatic limit when `max_db_size` is set high enough.
- `max_db_size`
  Absolute SQLite file size ceiling for inspection.
- `max_tables`
  Maximum number of interesting tables sampled from one database.
- `max_rows_per_table`
  Maximum number of sampled rows per interesting table.
- `max_cell_bytes`
  Maximum bytes read from one interesting cell value.
- `max_total_bytes`
  Maximum total bytes processed across all sampled SQLite cell values in one database.
- `max_interesting_columns`
  Maximum number of high-signal columns sampled per table.

Behavior notes:

- Snablr prioritizes table names such as `users`, `credentials`, `tokens`, `accounts`, `config`, and `settings`
- Snablr prioritizes column names such as `password`, `secret`, `token`, `api_key`, `connection_string`, and `dsn`
- placeholder-like values stay suppressed
- SQLite findings are reported with a combined path such as `app.db::users.password`
- remote scans never inspect SQLite on the target side; the database file is read and inspected locally

## `suppression`

The `suppression` section controls explicit allowlisting for known-benign findings in live environments.

Example:

```yaml
suppression:
  file: examples/suppressions.production.yaml
  sample_limit: 15
  rules:
    - id: allowlist-payroll-config-review
      description: Suppress reviewed payroll app findings in a known path family.
      reason: Known internal application config reviewed and accepted.
      enabled: true
      shares: [Finance]
      rule_ids: [content.password_assignment_indicators]
      path_prefixes: [Apps/Payroll/]
      path_contains: [internal-payroll]
```

Fields:

- `file`
  Optional external YAML overlay that contributes additional suppression rules.
- `sample_limit`
  Maximum number of suppressed sample findings to include in JSON and HTML summaries.
- `rules`
  Inline suppression rules.

Suppression rule fields:

- `id`
  Required stable identifier used in reports and audit summaries.
- `description`
  Optional operator-facing description.
- `reason`
  Required explanation of why the suppression exists.
- `enabled`
  Enables or disables the rule.
- `hosts`
  Match only findings from specific hosts.
- `shares`
  Match only findings from specific shares.
- `rule_ids`
  Match only findings from specific rule IDs.
- `categories`
  Match only findings from specific categories.
- `exact_paths`
  Match only an exact normalized finding path.
- `path_prefixes`
  Match a normalized finding path subtree.
- `path_contains`
  Match known application or deployment context fragments in the normalized finding path.
- `fingerprints`
  Match exact normalized finding fingerprints for stable cross-run allowlisting.
- `tags`
  Match findings carrying specific tags.

Matching behavior:

- match lists are ORed within a field
- different populated fields are ANDed together
- suppressed findings are hidden from the primary output, but they remain visible in a separate suppression summary
- suppression happens before correlation reporting so known-benign findings do not inflate access-path summaries

## `rules`

Example:

```yaml
rules:
  rules_directory: ""
  fail_on_invalid: false
```

Fields:

- `rules_directory`
  Optional override for rule loading
- `fail_on_invalid`
  Fail startup instead of warning when rule validation fails

If `rules_directory` is empty, Snablr loads:

- `configs/rules/default`
- `configs/rules/custom`

Recommended practice:

- keep shipped defaults in `configs/rules/default`
- keep organization-specific rules in `configs/rules/custom`

## `output`

Example:

```yaml
output:
  output_format: all
  json_out: output/results.json
  html_out: output/report.html
  csv_out: output/findings.csv
  md_out: output/summary.md
  pretty: true
```

Fields:

- `output_format`
  Primary output mode
- `json_out`
  JSON report path
- `html_out`
  HTML report path
- `csv_out`
  Optional CSV sidecar path
- `md_out`
  Optional Markdown sidecar path
- `pretty`
  Pretty-print JSON output

Supported `output_format` values:

- `console`
- `json`
- `html`
- `all`

### Output Format Behavior

#### `console`

- prints findings directly to the terminal
- best for live operator feedback

#### `json`

- writes one machine-readable report
- best for automation, scripting, and baseline comparison

#### `html`

- writes one standalone browser report
- best for post-scan triage and remediation review

#### `all`

- combines console, JSON, and HTML
- recommended for most scans

Optional sidecar exports:

- `csv_out`
- `md_out`

These can be used together with any primary mode.

## Realistic Example Profiles

### Basic Direct-Target Scan

File:
- `examples/config.basic.yaml`

Use it when:
- you want to scan one known host
- you want JSON and HTML output immediately
- you do not need LDAP discovery

### Domain-Aware Scan

File:
- `examples/config.domain.yaml`

Use it when:
- you want LDAP discovery by default
- you want checkpoints for longer runs
- you want console, JSON, HTML, CSV, and Markdown output together

### Targeted Triage

File:
- `examples/config.targeted.yaml`

Use it when:
- you want to validate a high-value share quickly
- you want to limit work with share/path filters
- you want a narrower triage run instead of a broad environment sweep

### Production Live-Environment Scan

File:
- `examples/config.production.yaml`

Use it when:
- you want the recommended balanced production profile
- you want resumable JSON, HTML, CSV, and Markdown output
- you want a clean suppression overlay for reviewed benign findings

## CLI Override Examples

Override credentials:

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --user 'DOMAIN\user' \
  --pass 'REPLACE_ME'
```

Override output locations:

```bash
snablr scan \
  --config examples/config.basic.yaml \
  --json-out output/basic.json \
  --html-out output/basic.html \
  --csv-out output/basic.csv \
  --md-out output/basic.md
```

Override scope:

```bash
snablr scan \
  --config examples/config.targeted.yaml \
  --share Finance \
  --path Payroll/ \
  --exclude-path Payroll/Old/
```

Override discovery behavior:

```bash
snablr scan \
  --config examples/config.domain.yaml \
  --dc dc01.example.local \
  --base-dn 'OU=Servers,DC=example,DC=local'
```
