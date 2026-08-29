# Architecture

Snablr is built as a modular Go codebase with clear boundaries between discovery, transport, scanning, planning, state, and output.

The main design goal is to keep rule management easy to maintain without tightly coupling rules, SMB, and reporting logic together.

## Package Structure

### `cmd/snablr`

CLI entrypoint.

Responsibilities:

- parse commands and flags
- load the banner
- hand off to the application layer

### `internal/app`

Runtime orchestration.

Responsibilities:

- load config
- apply CLI overrides
- initialize logging, rules, output, checkpoints, metrics, and progress reporting
- run the full scan flow

### `internal/config`

Configuration loading and defaults.

Responsibilities:

- load YAML config
- apply built-in defaults
- expose parsed runtime settings

### `internal/discovery`

Target discovery and preparation.

Responsibilities:

- parse CLI targets and target files
- determine domain context
- discover LDAP targets
- discover DFS-linked targets
- perform reachability testing
- normalize discovered hosts into the target pipeline

### `internal/smb`

SMB transport and file access.

Responsibilities:

- authenticate with username and password
- enumerate shares
- collect share metadata
- walk directories
- read file contents on demand

This package does not contain detection logic.

### `internal/planner`

Priority planning.

Responsibilities:

- assign priority to hosts, shares, and files
- keep scoring explainable
- ensure likely high-value work is scanned earlier

### `internal/rules`

Rule management and testing.

Responsibilities:

- YAML schema
- loading all rule files
- validation
- duplicate and regex checks
- rule filtering by type
- offline rule testing against fixtures

### `internal/scanner`

Rule-driven scanning engine.

Responsibilities:

- filename matching
- extension matching
- content matching
- worker-pool execution
- finding construction

This layer does not know about LDAP discovery and does not own SMB connectivity.

### Offline artifact pipeline

- `internal/artifact` owns bounded file-backed artifact identities and metadata.
- `internal/artifactbundle` correlates related artifacts such as SAM + SYSTEM and SECURITY + SYSTEM while enforcing origin boundaries.
- `internal/registryhive` provides reusable REGF hive parsing.
- `internal/systemkey` derives the SYSTEM boot key needed for offline SAM decoding.
- `internal/samparse` parses validated offline SAM account data without exposing raw hashes in normal output.
- `internal/securityparse` derives the modern LSA protection key and parses bounded SECURITY secret/cache metadata without returning raw secret bytes.
- `internal/ntdsparse` uses a read-only ESE catalog/table reader, reuses the SYSTEM boot key, decrypts the supported NTDS PEK/current NT hash attributes, and returns account metadata without serializing hash bytes.
- `internal/artifactbundle` pairs `NTDS.DIT` with `SYSTEM` only within the same normalized loose or WIM origin before NTDS analysis.
- `internal/smbkerberos` implements the pure-Go SMB Kerberos mechanism used by the patched SMB dependency.

### Post-scan credential analysis

`internal/credentialanalysis` is the shared in-memory classification model used by the JSON, HTML, and explicit credential exporters. Deep parsers and structured finding producers submit credential candidates with provenance. The analyzer normalizes, correlates only within producer-defined structure, deduplicates while retaining evidence, and classifies material as `confirmed` or `review`. Finding priority (`primary`/`supporting`) remains a separate axis. Filename and path-only findings are not exported as credentials, while uncertain extracted material is retained for review rather than silently discarded.

Confirmed status is based on offline structural or cryptographic evidence, such as SAM/SYSTEM or NTDS/SYSTEM recovery, and never on authentication. The post-scan layer has no transport or authentication dependency and never attempts SMB, LDAP, WinRM, RDP, SQL, SSH, HTTP, Kerberos, or NTLM validation with recovered values. Raw values remain ephemeral in normal reporters; `--creds-out` is an explicitly highly-sensitive export.

### `internal/output`

Findings rendering and export.

Responsibilities:

- console output
- JSON report generation
- HTML report generation
- CSV export
- Markdown summary export

### `internal/state`

Checkpoint/resume and credential-independent incremental scan state.

Responsibilities:

- record completed hosts, shares, and files
- write checkpoint JSON safely
- skip completed work on resumed runs
- persist object status/metadata and opaque credential access observations
- keep directory/share discovery independent from content-inspection reuse

The incremental inventory is separate from exact checkpoint/resume state. Object records describe server/share/path metadata, scan semantics, and completion status; access observations associate an opaque credential context with an observed object. No credential secret is part of the persisted schema.

### `internal/metrics`

Lightweight runtime counters and phase timings.

Responsibilities:

- scan timing by phase
- target/share/file counters
- snapshots for output and progress reporting

### `internal/ui`

Operator-facing terminal UI helpers.

Responsibilities:

- banner loading
- progress reporting

### `internal/version`

Build metadata.

Responsibilities:

- embedded version, commit, and build date

## Scan Flow

The runtime path is intentionally staged:

1. config
2. discovery
3. reachability
4. planning
5. SMB enumeration
6. scanning
7. output

### 1. Config

The application layer loads:

- defaults
- YAML config
- CLI overrides

This produces the effective runtime settings for the current scan.

### 2. Discovery

Targets can come from:

- CLI targets
- target files
- LDAP discovery
- DFS discovery

LDAP is the default fallback when no explicit targets are supplied.

### 3. Reachability

Before scanning begins, targets can be checked for TCP `445` reachability. This avoids wasting time attempting SMB connections to unreachable systems.

### 4. Planning

The planner prioritizes:

- hosts
- shares
- files

Examples of high-priority inputs:

- SYSVOL
- NETLOGON
- DFS-discovered shares
- finance, HR, payroll, config, backup, export, and secret-oriented paths
- key, config, and script-heavy extensions

### 5. SMB Enumeration

For each reachable target:

- connect over SMB
- list accessible shares
- collect share metadata
- walk shares with scope filters applied early
- read content only when the scanner indicates it is needed

### 6. Scanning

The scanner applies:

- filename rules
- extension rules
- content rules

The worker pool processes files concurrently. Skip logic, size checks, and content-read eligibility are applied before expensive work where possible.

### 7. Output

Findings flow into one or more writers. These writers can produce:

- console output
- JSON
- HTML
- CSV
- Markdown

The output layer also consumes metrics snapshots and summary data.

## Design Principles

Snablr tries to preserve a few core principles:

- rules first
  - add, remove, edit, and disable detections without recompiling

- separation of concerns
  - SMB, discovery, scanning, state, and output are kept distinct

- explainability
  - rules, priorities, findings, and reports should be readable by operators

- graceful degradation
  - missing metadata or unreachable discovery paths should not crash the scan

- operator workflow
  - progress, checkpoints, HTML reporting, and offline rule testing are first-class features
