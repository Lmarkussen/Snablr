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
