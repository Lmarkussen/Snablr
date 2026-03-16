# Snablr Runtime Test Report

Date: 2026-03-16

This report captures a real runtime verification pass of `snablr` against the lab targets provided for this project.

Lab context used during this run:
- Domain: `evilhaxxor.local`
- DC01: `172.16.0.80`
- FS01: `172.16.0.90`
- Test account used: `snaffleuser`

## Verification Matrix

| Subsystem | Status | Notes |
| --- | --- | --- |
| build | PASS | `go mod tidy` and binary build completed successfully. |
| CLI | PASS | `version`, root help, and `scan --help` worked. |
| rules | PASS | Rules listed and validated cleanly. |
| SMB scanning | PASS | Direct scan against `172.16.0.90` succeeded, enumerated shares, scanned files, and produced findings. |
| LDAP discovery | PARTIAL | Default domain-aware scan failed LDAP bind with plain username format; explicit `--domain evilhaxxor.local` allowed discovery and returned 2 hosts, but both were marked unreachable for SMB. |
| output generation | PASS | JSON and HTML reports were generated and structurally valid for both successful and failed scans. |
| checkpoint/resume | PASS | Checkpoint file was written, resume skipped a completed share, and remaining work completed. |
| diff mode | PASS | Diff output rendered correctly between direct-scan and failed domain-scan result sets. |

## 1. Build Verification

### Commands

```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go mod tidy
env GOCACHE=/tmp/snabll-gocache go build -o snablr ./cmd/snablr
./snablr version
./snablr --help
./snablr scan --help
```

### Expected Result

- Module metadata remains valid.
- Binary builds successfully.
- `version` and help commands run without missing command errors.

### Actual Result

- `go mod tidy` completed with no output and no error.
- `go build -o snablr ./cmd/snablr` completed successfully.
- `./snablr version` printed:

```text
Snablr dev (commit: unknown, built: unknown)
```

- `./snablr --help` printed the top-level command list, examples, and authorized-use guidance.
- `./snablr scan --help` printed scan usage, examples, output format guidance, and the scan flags.

### Status

PASS

## 2. Rule System Verification

### Commands

```bash
./snablr rules list
./snablr rules validate
```

### Expected Result

- Rules load successfully.
- No validation errors are reported.

### Actual Result

- `rules list` printed enabled content, filename, extension, and skip rules, including:
  - `content.password_assignment_indicators`
  - `content.private_key_header_indicators`
  - `filename.credentials_and_secrets_keywords`
  - `filename.deployment_answer_files`
  - `extension.sensitive_config_extensions`
- `rules validate` printed:

```text
validated 6 rule files, no issues found
```

### Status

PASS

## 3. Direct SMB Scan Verification

### Command

```bash
./snablr scan \
  --targets 172.16.0.90 \
  --user snaffleuser \
  --pass 'Password123!' \
  --output-format all \
  --json-out results.json \
  --html-out report.html
```

### Expected Result

- Connection to FS01 succeeds.
- Shares are enumerated.
- Files are scanned without crashing.
- `results.json` and `report.html` are generated.

### Actual Result

Key runtime output:

```text
[INFO] Targets loaded: 1
[INFO] Unique targets: 1
[INFO] Reachable SMB hosts: 1
[INFO] Skipped hosts: 0
[INFO] scan plan prepared for 1 host(s); highest priority=35 (base host priority; explicit CLI target)
[INFO] scanning host 172.16.0.90
[INFO] walking 172.16.0.90/Archive ...
[INFO] walking 172.16.0.90/Scripts ...
[INFO] walking 172.16.0.90/Homes$ ...
[INFO] walking 172.16.0.90/Public ...
```

Representative findings:

```text
\\172.16.0.90\Archive\Users\Alice\Desktop\passwords.txt
\\172.16.0.90\Archive\Legacy\App1\Config\web.config
\\172.16.0.90\Archive\Legacy\App2\Config\unattend.xml
\\172.16.0.90\Scripts\Logon\map-drives.bat
\\172.16.0.90\Scripts\creds-test.txt
\\172.16.0.90\Public\password policy reminder.txt
```

Final summary:

```text
Summary: hosts=1 shares=4 files=159 matches=9 skipped=0 read_errors=0
Metrics: targets_loaded=1 targets_reachable=1 shares_enumerated=4 files_visited=159 files_skipped=0 files_read=158 matches_found=9
Phase Timings:
  host_scanning: 293ms
  reachability_check: 4ms
  total_scan: 298ms
```

### Status

PASS

## 4. Domain Discovery Scan Verification

### Command Requested

```bash
./snablr scan \
  --dc 172.16.0.80 \
  --user snaffleuser \
  --pass 'Password123!' \
  --output-format all \
  --json-out results-domain.json \
  --html-out report-domain.html
```

### Expected Result

- LDAP connection succeeds.
- Domain computers are discovered.
- Targets are deduplicated.
- Reachability testing runs.
- Reachable hosts are scanned.
- Reports are generated.

### Actual Result

Output:

```text
[INFO] no explicit targets supplied, starting ldap discovery
[INFO] ldap discovery: domain context method=hostname -d domain=(none) dc=172.16.0.80
ldap discovery: bind failed for snaffleuser@(none): LDAP Result Code 49 "Invalid Credentials" ... data 52e ...
```

The requested domain-aware scan did not reach host enumeration because the LDAP bind failed with the plain username format under the current autodetected domain context.

Artifacts were still generated:
- `results-domain.json`
- `report-domain.html`

Those artifacts were valid but empty:

```text
summary.hosts_scanned = 0
summary.shares_scanned = 0
summary.files_scanned = 0
summary.matches_found = 0
```

### Additional Diagnostic Command

```bash
./snablr discover \
  --domain evilhaxxor.local \
  --dc 172.16.0.80 \
  --user snaffleuser \
  --pass 'Password123!'
```

### Diagnostic Result

Output:

```text
[INFO] ldap discovery: searching base DN DC=evilhaxxor,DC=local
[INFO] ldap discovery: discovered 2 host(s)

Snablr Discovery Summary
Targets loaded: 2
Unique targets: 2
Reachable SMB hosts: 0
Skipped hosts: 2

LDAP hosts (2):
- DC01.evilhaxxor.local  os=Windows Server 2022 Standard Evaluation
- FS01.evilhaxxor.local  os=Windows Server 2022 Standard Evaluation
```

This shows:
- LDAP/DC connectivity works.
- RootDSE and computer enumeration work when an explicit domain is provided.
- The default requested scan path failed at bind/auth formatting.
- The explicit-domain diagnostic then failed at post-discovery SMB reachability for the discovered FQDNs.

### Status

PARTIAL

## 5. Output Verification

### Commands

```bash
ls -lh results.json report.html
python3 - <<'PY'
import json
with open('results.json','r',encoding='utf-8') as f:
    data=json.load(f)
print('summary', data.get('summary', {}))
print('metrics', data.get('metrics', {}))
print('findings', len(data.get('findings', [])))
print('category_summaries', len(data.get('category_summaries', [])))
PY
sed -n '1,120p' report.html
```

### Expected Result

- JSON is valid and populated.
- HTML is valid standalone markup.
- Summary fields are present.
- Findings include the expected metadata.

### Actual Result

- `results.json` size: about `22K`
- `report.html` size: about `69K`
- JSON parsed successfully.
- Parsed summary:

```text
hosts_scanned: 1
shares_scanned: 4
files_scanned: 159
matches_found: 9
skipped_files: 0
read_errors: 0
```

- Parsed metrics:

```text
targets_loaded: 1
targets_reachable: 1
shares_enumerated: 4
files_visited: 159
files_read: 158
matches_found: 9
```

- `findings`: `9`
- `category_summaries`: `4`
- The first finding included:
  - `rule_id`
  - `file_path`
  - `confidence`
  - `confidence_score`
  - `matched_rule_ids`
  - `matched_signal_types`
  - `supporting_signals`
  - `remediation_guidance`

- `report.html` began with a valid `<!DOCTYPE html>` document and embedded CSS.

### Status

PASS

## 6. Checkpoint / Resume Verification

### Commands

```bash
./snablr scan \
  --targets 172.16.0.90 \
  --user snaffleuser \
  --pass 'Password123!' \
  --checkpoint-file scan.state \
  --max-scan-time 50ms \
  --output-format all \
  --json-out results-checkpoint.json \
  --html-out report-checkpoint.html

./snablr scan \
  --targets 172.16.0.90 \
  --user snaffleuser \
  --pass 'Password123!' \
  --checkpoint-file scan.state \
  --resume \
  --output-format all \
  --json-out results-checkpoint.json \
  --html-out report-checkpoint.html
```

### Expected Result

- A checkpoint file is written.
- Resume consumes that state.
- Already completed work is skipped.

### Actual Result

First run output included:

```text
[WARN] max scan time reached; stopping scan gracefully
Summary: hosts=1 shares=4 files=0 matches=0 skipped=0 read_errors=0
```

Checkpoint file contents:

```json
{
  "version": 1,
  "updated_at": "...",
  "completed_shares": [
    "172.16.0.90::homes$"
  ]
}
```

Resume run output included:

```text
[INFO] resume: skipping completed share 172.16.0.90/Homes$
Summary: hosts=1 shares=3 files=159 matches=9 skipped=0 read_errors=0
```

### Status

PASS

## 7. Diff Mode Verification

### Command

```bash
./snablr diff --old results.json --new results-domain.json
```

### Expected Result

- Diff summary renders cleanly.
- New/removed/changed/unchanged counts are shown.

### Actual Result

Output:

```text
Snablr Diff Summary
New: 0
Removed: 9
Changed: 0
Unchanged: 0
```

Removed findings were listed correctly, including:
- `\\172.16.0.90\Archive\Users\Alice\Desktop\passwords.txt`
- `\\172.16.0.90\Archive\Legacy\App1\Config\web.config`
- `\\172.16.0.90\Archive\Legacy\App2\Config\unattend.xml`

### Status

PASS

## Errors Encountered

1. The requested domain-aware scan with:

```bash
--dc 172.16.0.80 --user snaffleuser --pass 'Password123!'
```

failed LDAP bind with:

```text
LDAP Result Code 49 "Invalid Credentials" ... data 52e
```

2. With explicit `--domain evilhaxxor.local`, LDAP discovery succeeded and returned `DC01.evilhaxxor.local` and `FS01.evilhaxxor.local`, but both were marked unreachable for SMB from the reachability stage.

## Fixes Applied During This Run

No code fixes were applied as part of this verification pass.

## Overall Runtime Health

Snablr is healthy on the direct SMB scan path:
- build works
- CLI works
- rule loading works
- direct scanning against FS01 works
- JSON and HTML outputs are generated and populated
- checkpoint/resume works
- diff mode works

The domain-aware path is partially healthy:
- LDAP/DC connectivity and LDAP enumeration can work with an explicit domain override
- the exact requested domain-aware command failed at bind/auth formatting
- the explicit-domain diagnostic then failed at SMB reachability for discovered FQDN targets

## Recommendation

Before broader use, validate the domain-aware flow with one of these approaches:
- retry with `--domain evilhaxxor.local`
- retry with a domain-qualified username such as `snaffleuser@evilhaxxor.local`
- confirm name resolution or reachability for `DC01.evilhaxxor.local` and `FS01.evilhaxxor.local`

At the time of this report, the safest proven operator workflow is the direct target scan path against reachable SMB hosts.
