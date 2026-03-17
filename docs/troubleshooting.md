# Troubleshooting

This guide covers common operational issues when running Snablr.

## Command Not Found

### Symptom

Your shell reports:

- `snablr: command not found`

### What To Do

- if you built from source, run `./bin/snablr --help`
- if you downloaded a release, run the binary from the extracted folder
- if you want `snablr` available globally, move it into a directory on your `PATH`

Quick verification:

```bash
./bin/snablr version
```

## Go Not Installed

### Symptom

Build commands fail because `go` is missing.

### What To Do

- install Go `1.24+`
- verify with `go version`
- then rerun:

```bash
go build ./...
make build
```

## Build Failed

### Symptom

`go build`, `make build`, or `make test` fails.

### What To Check

- run `go version` and confirm Go `1.24+`
- run `go mod tidy`
- run `go build ./...`
- run `go test ./...`
- if you are only trying to verify the project quickly, use `go build ./...` first and then `make build`

## LDAP Discovery Issues

### Symptom

No targets are discovered when running:

```bash
./bin/snablr scan --user 'EXAMPLE\user' --pass 'REPLACE_ME'
```

### Common Causes

- the host is not domain-connected
- LDAP connectivity to a domain controller is blocked
- domain detection failed
- the supplied credentials do not work for LDAP bind
- the server requires signing or stronger authentication and LDAPS is not reachable

### What To Check

- try `--domain <fqdn>` explicitly
- try `--dc <hostname>` explicitly
- try `--base-dn 'DC=example,DC=local'` explicitly
- raise logging with `--log-level debug`
- confirm port and name resolution to the target DC

Current bind behavior:

- Snablr attempts LDAP simple bind first
- if the server returns stronger-auth-required or confidentiality-required style errors, Snablr retries over LDAPS automatically
- if both `389` and `636` are blocked or unusable, LDAP discovery still fails and explicit targets are the right fallback

If LDAP discovery remains unreliable, fall back to explicit targets until domain context is confirmed.

## No Targets Found

### Symptom

Snablr exits with an error explaining that no reachable SMB targets are available.

### Common Causes

- the provided target list was empty
- LDAP discovery returned nothing useful
- reachability checks filtered out all hosts
- SMB hosts are offline or blocked

### What To Check

- provide an explicit target with `--targets`
- use `snablr discover --help` to inspect discovery behavior
- verify you did not accidentally set `--no-ldap` without also providing targets
- use `--skip-reachability-check` only when you intentionally want to inspect hosts even if TCP `445` probes fail

## DC Detection Issues

### Symptom

Domain context is partially detected, but Snablr cannot find a domain controller automatically.

### Common Causes

- SRV lookups for `_ldap._tcp.dc._msdcs.<domain>` fail
- DNS search/domain configuration is incomplete
- environment-derived domain values are wrong

### What To Check

- specify `--dc` manually
- specify `--domain` manually
- confirm DNS resolution and SRV records
- review the selected detection method in debug logs

If SRV discovery fails but you know a usable DC, passing `--dc` is the clean fallback.

## SMB Authentication Issues

### Symptom

Connections fail during share enumeration or file reads.

### Common Causes

- invalid username or password
- incorrect domain-qualified username
- SMB signing or policy requirements outside the current access path
- host reachable, but credentials do not have share access

### What To Check

- try `EXAMPLE\user`
- try `user@domain`
- confirm the account can access the share manually
- use `--skip-reachability-check` only if you are sure the host is reachable and want to bypass the TCP probe

Also verify that permission-denied shares are expected. Snablr will skip inaccessible shares rather than crashing.

## HTML Report Not Generated

### Symptom

The scan ran, but the expected HTML report file does not exist.

### What To Check

- confirm `--output-format html` or `--output-format all`
- confirm `--html-out` is set, or that your config file sets `output.html_out`
- confirm the output directory is writable
- check the terminal for any final output writer error

Minimal known-good example:

```bash
./bin/snablr scan \
  --targets 10.0.0.5 \
  --user 'EXAMPLE\user' \
  --pass 'REPLACE_ME' \
  --output-format html \
  --html-out report.html
```

## Empty JSON Output

### Symptom

The JSON file exists, but it contains no findings.

### What To Check

- verify the scan actually completed
- confirm you used `--output-format json` or `--output-format all`
- review filters such as `share`, `exclude_share`, `path`, `exclude_path`, and `max_depth`
- confirm the rule pack is valid with `snablr rules validate`
- test expected matches directly with `snablr rules test`

## No Findings

### Symptom

A scan finishes cleanly, but no findings are produced.

### Common Causes

- the active rule pack is too narrow for the environment
- share or path filters are too restrictive
- `max_file_size` is excluding relevant files
- content rules are disabled or path-limited
- only low-value or excluded areas were scanned

### What To Check

- run `snablr rules validate`
- run `snablr rules list`
- inspect `share`, `exclude_share`, `path`, `exclude_path`, and `max_depth`
- confirm `max_file_size` is not too low
- test likely matching sample files with `rules test`

For targeted verification, run against known-safe fixtures first before assuming a scan issue.

## Too Many Findings

### Symptom

The scan produces excessive noise or many low-value matches.

### Common Causes

- broad filename keywords
- PII-like or generic token rules
- insufficient `exclude_paths`
- wide extension coverage on noisy shares

### What To Check

- review `docs/tuning.md`
- disable noisy rules temporarily with `enabled: false`
- narrow `file_extensions`
- add `include_paths`
- expand `exclude_paths`

Recommended tuning order:

1. path filters
2. extensions
3. enablement
4. regex changes

## Performance Tuning

### Symptom

The scan is correct, but too slow or too memory-heavy for the environment.

### Current Optimizations

- adaptive worker scaling when `worker_count` is `0`
- early content-read skipping when content rules are extension-scoped
- bounded batch planning during share walks
- max file size checks before expensive reads

### What To Tune

- leave `worker_count` at `0` first, then pin it only if necessary
- lower `max_file_size` for very broad scans
- narrow with `share`, `exclude_share`, `path`, `exclude_path`, and `max_depth`
- use `only_ad_shares` or `prioritize_ad_shares` when reviewing AD-heavy environments
- use `max_scan_time` for bounded review windows

See also:

- `docs/performance.md`

## Resume And Checkpoint Issues

### Symptom

`--resume` does not behave as expected, or work appears to be rescanned.

### Common Causes

- the checkpoint file path changed between runs
- the first run did not finish enough work to mark some shares or files complete
- the checkpoint file was removed or overwritten
- files changed size or modified timestamp between runs

### What To Check

- confirm the same `--checkpoint-file` is being reused
- inspect the checkpoint JSON directly
- ensure the scan is not being restarted with a different host naming form
- confirm the share/path filters are consistent between runs
- confirm whether the files actually changed between runs

Checkpoint behavior is designed to stay usable even for interrupted scans. Partial file completion should still be retained, and subsequent resumed runs should continue from the remaining work. Completed-file entries are invalidated when file size or modified timestamp changes.

## Time Limit Reached

### Symptom

The scan stops earlier than expected.

### Common Cause

- `--max-scan-time` or `scan.max_scan_time` is set

### What To Expect

- the scan stops gracefully
- partial results are still written
- checkpoints remain usable
- progress output marks that the time limit was reached

If this is expected, rerun with `--resume` to continue later. If it is not expected, check the loaded config and CLI overrides.
