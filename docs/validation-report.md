# Snablr Validation Report

Date: 2026-03-16

Scope:
- Full validation pass covering build/tooling, CLI, rules, output/reporting, discovery, checkpoint/resume, diff mode, seeder verification, and release packaging.
- Lab context provided:
  - Domain: `evilhaxxor.local`
  - DC01: `172.16.0.80`
  - FS01: `172.16.0.90`

Environment notes:
- Local build/test execution was performed with isolated Go caches under `/tmp`.
- Live TCP/445 reachability to the provided lab hosts was verified.
- Live LDAP discovery and authenticated SMB enumeration/scanning were not fully environment-verified because no valid lab credentials were provided in this session.

## Validation Matrix

| Subsystem | Status | Verification Level | Confidence | Notes |
| --- | --- | --- | --- | --- |
| Build & Tooling | PASS | build-verified, unit-test-verified | High | `go mod tidy`, `go build`, `go test`, `go vet`, `make` targets passed |
| CLI | PASS | build-verified | High | Top-level and subcommand help paths verified |
| Rules | PASS | build-verified, unit-test-verified | High | Happy path and negative-path validation verified |
| Output & Reports | PASS | unit-test-verified, build-verified | Medium-High | JSON/HTML/console/CSV/Markdown verified via tests; one diff path formatting bug fixed |
| Discovery | PARTIAL | unit-test-verified, environment-verified | Medium | Explicit targets, dedup, and live reachability verified; live LDAP not verified |
| SMB Scan Path | PARTIAL | environment-verified, unit-test-verified | Medium-Low | Live auth-failure path verified; successful authenticated share enumeration not verified |
| Resume / Checkpoint | PASS | unit-test-verified, build-verified, partial environment-verified | High | Corrupt checkpoint rejection and failed-scan checkpoint creation verified |
| Diff Mode | PASS | build-verified, unit-test-verified | High | CLI diff and parse-failure path verified; UNC output bug fixed |
| Seeder / Manifest | PASS | unit-test-verified, build-verified | Medium-High | Verification flow and CLI verified; live SMB seeding not verified |
| Release / Packaging | PASS | build-verified | High | `make release-snapshot` and archive contents verified |

## Build & Tooling

Command:
```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go mod tidy
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go build ./...
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go test ./...
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go vet ./...
```

Expected result:
- Module graph tidy
- Full project build success
- Test suite pass
- `go vet` pass

Actual result:
- All commands succeeded

Status: PASS

Additional packaging/tooling checks:
```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache make build
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache make test
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache make lint
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache make release-snapshot VERSION=v0.1.1-validate
```

Actual result:
- All targets succeeded

Status: PASS

## CLI

Commands:
```bash
/tmp/snablr-validate --help
/tmp/snablr-validate scan --help
/tmp/snablr-validate rules --help
/tmp/snablr-validate discover --help
/tmp/snablr-validate diff --help
/tmp/snablr-validate version
```

Expected result:
- Commands visible and discoverable
- Flags consistent (`--username`/`--password` with aliases)
- Examples sensible
- `version` returns version metadata

Actual result:
- Help output was present and coherent for all requested commands
- Examples covered direct scan, config-based scan, reporting, discovery, rule testing, and diff mode
- `version` worked
- Plain local ad-hoc binary builds report `commit: unknown, built: unknown` unless ldflags are used, which is expected

Status: PASS

## Rules

Commands:
```bash
/tmp/snablr-validate rules list --config configs/config.yaml
/tmp/snablr-validate rules validate --config configs/config.yaml
/tmp/snablr-validate rules test --rule configs/rules/default/content.yml --input testdata/rules/fixtures/content/password-assignment.conf --verbose
/tmp/snablr-validate rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose
```

Expected result:
- Rules load
- Validation succeeds for default packs
- Single-file and directory tests match expected fixtures
- Exit code `2` on match

Actual result:
- Default rules loaded correctly
- Validation succeeded with `validated 6 rule files, no issues found`
- `rules test` matched `content.password_assignment_indicators` with snippet and returned `EXIT:2`
- `rules test-dir` matched 14 findings across 6 fixtures and returned `EXIT:2`

Status: PASS

Negative-path validation:
```bash
/tmp/snablr-validate rules validate --rules-directory <temp-invalid-regex-dir>
/tmp/snablr-validate rules validate --rules-directory <temp-duplicate-id-dir>
/tmp/snablr-validate rules test --rule <temp-no-match-rule> --input testdata/rules/fixtures/content/password-assignment.conf --verbose
```

Expected result:
- Invalid regex rejected
- Duplicate IDs surfaced
- No-match path returns exit code `0`

Actual result:
- Invalid regex produced a warning and `EXIT:1`
- Duplicate ID produced a warning and `EXIT:1`
- No-match path returned `EXIT:0`

Status: PASS

## Output & Reports

Commands:
```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go test -run 'Test(JSONWriter|ConsoleWriter|HTMLWriter|CSVWriter|MarkdownWriter)' -v ./internal/output
```

Expected result:
- Structured JSON report generation
- HTML standalone report generation
- Console, CSV, and Markdown outputs contain expected metadata

Actual result:
- Output-focused tests passed:
  - JSON report structure
  - diff summary in JSON
  - HTML standalone rendering
  - HTML diff summary rendering
  - console metadata output
  - CSV and Markdown exports

Status: PASS

Fix applied during validation:
- Diff CLI exposed malformed UNC output paths:
  - Before: `\\fs01\financeconfig\db.conf`
  - After: `\\fs01\finance\config\db.conf`
- Fixed in:
  - `internal/app/runtime.go`
  - `internal/output/writer.go`

Retest command:
```bash
/tmp/snablr-validate diff --old <synthetic-old.json> --new <synthetic-new.json>
```

Actual result after fix:
- UNC paths rendered correctly in diff output

Status: PASS

## Discovery

Commands:
```bash
/tmp/snablr-validate discover --targets-file /tmp/snablr-targets.txt --skip-reachability-check --no-ldap
/tmp/snablr-validate discover --no-ldap
/tmp/snablr-validate discover --domain evilhaxxor.local --dc 172.16.0.80
/tmp/snablr-validate discover --targets 172.16.0.80,172.16.0.90 --no-ldap --reachability-timeout 2
```

Expected result:
- Explicit target dedup works
- No-target/no-LDAP path errors clearly
- Domain/DC override path enforces LDAP credentials
- Live reachability testing identifies reachable hosts

Actual result:
- Explicit target file with duplicate entries reported:
  - `Targets loaded: 3`
  - `Unique targets: 2`
  - Reachable targets shown correctly
- `discover --no-ldap` failed with actionable error
- Domain/DC override without creds failed with actionable LDAP credential error
- Live reachability to `172.16.0.80` and `172.16.0.90` succeeded:
  - `Reachable SMB hosts: 2`

Status: PARTIAL

Not verified:
- Live LDAP bind and computer enumeration
- Live DFS discovery
- Domain auto-detection against a real joined host in this environment

## SMB Scan Path

Command:
```bash
/tmp/snablr-validate scan --targets 172.16.0.90 --username fake --password fake --no-ldap --skip-reachability-check --output-format console --max-scan-time 30s
```

Expected result:
- Scan orchestration starts
- Planning and progress summary occur
- SMB auth failure is surfaced clearly
- Clean shutdown with summary output

Actual result:
- Target loading, planning, metrics, and summary all executed
- Live SMB auth failure was reported clearly:
  - `connect failed: authenticate to 172.16.0.90: response error: The attempted logon is invalid...`

Status: PARTIAL

Not verified:
- Successful authenticated share enumeration
- Live file walking
- Live filtering over real shares
- Live report generation from an authenticated scan

## Resume / Checkpoint

Commands:
```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go test -run 'TestStore|TestManager' -v ./internal/state
/tmp/snablr-validate scan --targets 172.16.0.90 --username fake --password fake --no-ldap --skip-reachability-check --resume --checkpoint-file <bad-json>
/tmp/snablr-validate scan --targets 172.16.0.90 --username fake --password fake --no-ldap --skip-reachability-check --checkpoint-file <new-file>
```

Expected result:
- State round-trips
- Incremental share completion works
- Corrupt checkpoint rejected safely
- Failed scan still leaves usable checkpoint state

Actual result:
- State unit tests passed
- Corrupt checkpoint was rejected with:
  - `open checkpoint state: parse checkpoint file ...`
- Failed live scan still wrote a readable checkpoint JSON:
```json
{
  "version": 1,
  "updated_at": "2026-03-15T23:56:50.786144369Z"
}
```

Status: PASS

## Diff Mode

Commands:
```bash
/tmp/snablr-validate diff --old <synthetic-old.json> --new <synthetic-new.json>
/tmp/snablr-validate diff --old <bad.json> --new <bad.json>
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go test -run TestCompare -v ./internal/diff
```

Expected result:
- New/removed/changed/unchanged counts correct
- Parse failures return exit code `1`
- Changed fields include severity deltas where expected

Actual result:
- CLI diff reported:
  - `New: 1`
  - `Removed: 1`
  - `Changed: 1`
  - `Unchanged: 1`
- Parse failure returned `EXIT:1`
- Diff unit tests passed

Status: PASS

## Seeder / Manifest

Commands:
```bash
/tmp/snablr-seed-validate --help
/tmp/snablr-seed-validate verify --help
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache go test -run TestVerify -v ./internal/seed
/tmp/snablr-seed-validate verify --manifest <synthetic-manifest.json> --results <synthetic-results.json>
```

Expected result:
- Seeder CLI discoverable
- Verification reports found/missed/unexpected items
- Category coverage rendered clearly

Actual result:
- Seeder help and verify help were coherent
- Verify unit test passed
- CLI verify reported:
  - `Expected items: 2`
  - `Expected items found: 1`
  - `Expected items missed: 1`
  - `Unexpected findings: 1`
  - Coverage by category

Status: PASS

Not verified:
- Live SMB seeding with valid credentials

## Release / Packaging

Commands:
```bash
env GOCACHE=/tmp/snablr-gocache GOMODCACHE=/tmp/snablr-gomodcache make release-snapshot VERSION=v0.1.1-validate
find dist -maxdepth 1 -type f -printf '%f\n' | sort
tar -tzf dist/snablr_v0.1.1-validate_linux_amd64.tar.gz | sort | sed -n '1,20p'
unzip -l dist/snablr_v0.1.1-validate_windows_amd64.zip | sed -n '1,20p'
<extracted-linux-binary> version
```

Expected result:
- Full target matrix built
- Archive names match release convention
- Archives include `README.md` and `LICENSE`
- Snapshot binary reports injected version metadata

Actual result:
- Produced:
  - `snablr_v0.1.1-validate_linux_amd64.tar.gz`
  - `snablr_v0.1.1-validate_linux_arm64.tar.gz`
  - `snablr_v0.1.1-validate_darwin_amd64.tar.gz`
  - `snablr_v0.1.1-validate_darwin_arm64.tar.gz`
  - `snablr_v0.1.1-validate_windows_amd64.zip`
- Linux and Windows archives contained binary + `README.md` + `LICENSE`
- Extracted Linux snapshot binary reported:
  - `Snablr v0.1.1-validate (commit: 967414e, built: 2026-03-15T23:57:14Z)`

Status: PASS

## Fixes Applied

1. Fixed malformed UNC path rendering in diff/console output.
   - Files:
     - `internal/app/runtime.go`
     - `internal/output/writer.go`
2. Retested output and diff flows after the fix.

## Remaining Issues

1. Live authenticated LDAP discovery is not verified in this session.
2. Live authenticated SMB share enumeration, file walking, and report generation are not verified in this session.
3. Local ad-hoc `go build` binaries show `unknown` commit/build metadata unless built with ldflags or Makefile/release targets. This is expected, but operators should use `make build` or release artifacts when they want embedded metadata.

## Overall Assessment

Verdict:
- Snablr is in good shape for build/test/release quality and for offline operator workflows.
- The main functional defect found in this validation pass was the malformed UNC path rendering in diff/console output, and it has been fixed and retested.
- The largest remaining gap is authenticated live environment verification for LDAP and SMB scan success paths.

Recommended next steps before broader use:
1. Run a credentialed live validation against `DC01` and `FS01` to verify:
   - LDAP bind and computer enumeration
   - SMB share listing
   - file walking
   - HTML/JSON report output from a real scan
2. Use the lab seeder with valid SMB credentials to seed controlled content and verify end-to-end detection coverage against `snablr` scan outputs.
3. Capture one real HTML report artifact and one real JSON result artifact for ongoing regression validation.
