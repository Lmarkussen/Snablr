# Configuration

Snablr can be configured with a YAML file, CLI flags, or both.

The default runtime config file is `configs/config.yaml`. Several example profiles also live under `examples/`.

## How Configuration Works

Snablr loads configuration in this order:

1. built-in defaults
2. YAML config file
3. CLI flag overrides

That means CLI flags always win over config values for the current run.

Example:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --share SYSVOL \
  --max-scan-time 30m
```

In this example, the config file is loaded first, then `--share` and `--max-scan-time` override the loaded values.

## Top-Level Sections

Snablr config is grouped into:

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
  Display name used by the application. In practice this should remain `snablr`.

- `log_level`
  Logging verbosity.
  Common values: `debug`, `info`, `warn`, `error`

- `banner_path`
  Runtime path to the banner ASCII art file.

## `scan`

The `scan` section controls discovery, scope, concurrency, and runtime behavior.

### Target Selection

- `targets`
  Explicit host list. If this is set, Snablr uses these targets directly.

- `targets_file`
  Path to a file containing one target per line.

If both `targets` and `targets_file` are empty, Snablr can fall back to LDAP discovery unless disabled.

### Credentials

- `username`
  SMB and LDAP username.

- `password`
  SMB and LDAP password.

Use placeholders in committed configs. Inject real credentials at runtime through CLI overrides or local secrets handling.

### Scan Scope Filters

- `share`
  Only scan these share names.

- `exclude_share`
  Skip these share names.

- `path`
  Only scan files under these path prefixes.

- `exclude_path`
  Skip files under these path prefixes.

- `max_depth`
  Maximum directory recursion depth during share walking.

These filters are applied early so they reduce workload before the scanner spends time on unnecessary files.

### Performance Controls

- `worker_count`
  File scanning worker count.

  `0` means adaptive worker scaling. This is the recommended default for most environments.

- `max_file_size`
  Maximum file size Snablr will consider for scanning.

Large values increase scan coverage but also increase I/O and memory pressure.

### Discovery Controls

- `no_ldap`
  Disable LDAP discovery when no explicit targets are supplied.

- `domain`
  Explicit domain name override for discovery.

- `dc`
  Explicit domain controller override.

- `base_dn`
  Explicit LDAP search base override.

- `discover_dfs`
  Enable DFS discovery so linked enterprise shares can be added to the pipeline.

### Planning Controls

- `prioritize_ad_shares`
  Prefer SYSVOL and NETLOGON during planning.

- `only_ad_shares`
  Restrict scanning to SYSVOL and NETLOGON.

### Runtime Limits And Resume

- `max_scan_time`
  Total scan time limit, for example `30m` or `2h`.

- `checkpoint_file`
  JSON checkpoint path for resumable scans.

- `resume`
  Resume from an existing checkpoint file.

### Reachability

- `skip_reachability_check`
  Disable TCP `445` reachability testing.

- `reachability_timeout_seconds`
  Timeout for SMB reachability tests.

## `rules`

Example:

```yaml
rules:
  rules_directory: ""
  fail_on_invalid: false
```

Fields:

- `rules_directory`
  Optional override for rule loading.

  If empty, Snablr loads the default locations:

  - `configs/rules/default`
  - `configs/rules/custom`

- `fail_on_invalid`
  If set, rule validation errors fail startup rather than only warning.

Recommended use:

- leave defaults and custom rules separate
- enable strict validation in CI or controlled environments

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
  Primary output mode.

  Supported values:

  - `console`
  - `json`
  - `html`
  - `all`

- `json_out`
  Path to the JSON report when JSON output is enabled.

- `html_out`
  Path to the HTML report when HTML output is enabled.

- `csv_out`
  Optional sidecar CSV findings export.

- `md_out`
  Optional sidecar Markdown summary export.

- `pretty`
  Controls pretty-printed JSON formatting.

## Output Format Behavior

### `console`

- findings print to the terminal
- best for interactive use
- progress reporting can appear when running in a terminal

### `json`

- writes one machine-readable JSON report
- best for automation or downstream parsing

### `html`

- writes one standalone browser-friendly report
- best for post-scan review

### `all`

- combines console, JSON, and HTML
- recommended for most real scans

Optional sidecar exports:

- `csv_out`
- `md_out`

These can be used with any primary output mode.

## CLI Override Examples

Use a config file, but override one field:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --max-scan-time 45m
```

Override credentials only:

```bash
./bin/snablr scan \
  --config examples/config.targeted.yaml \
  --user 'DOMAIN\user' \
  --pass 'REPLACE_ME'
```

Override output paths:

```bash
./bin/snablr scan \
  --config examples/config.basic.yaml \
  --json-out output/basic.json \
  --html-out output/basic.html \
  --csv-out output/basic.csv \
  --md-out output/basic.md
```

## Recommended Config Profiles

- `examples/config.basic.yaml`
  Minimal direct-target scan with JSON and HTML output

- `examples/config.domain.yaml`
  Domain-aware scan with LDAP discovery, checkpoints, and full report output

- `examples/config.targeted.yaml`
  Narrow scope triage using share and path filters
