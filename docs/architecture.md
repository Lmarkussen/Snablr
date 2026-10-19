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
- initialize logging, rules, output, scan database, metrics, and progress reporting
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

### `internal/findings`

The Findings Engine reopens persisted SQLite scan state without contacting
SMB. Its provider loads scanner findings, credential material, source
observations, and contextual correlations read-only. The Finder TUI projects
that data into category and subcategory navigation, logical discoveries, and
a scrollable Details pane with evidence and provenance.

The projection keeps these concepts separate:

- scanner-produced findings are raw detection records
- persisted rows are stored material and evidence records
- logical discoveries group equivalent material for review
- source observations identify each contributing file or archive member
- correlations describe contextual relationships and are not confirmed pairs

Credential analysis preserves scope-aware username/password relationships,
Review classifications, duplicate observations, archive-member paths, and
Unicode values. Finder presentation does not authenticate or otherwise test
discovered credentials.

### `internal/state`

Authoritative SQLite scan state and credential-independent object metadata.

Responsibilities:

- record completed hosts, shares, and files
- write authoritative SQLite state safely
- skip completed work on resumed runs
- persist object status/metadata and opaque credential access observations
- keep directory/share discovery independent from content-inspection reuse

The scan database stores exact resume state. Object records describe server/share/path metadata, scan semantics, and completion status; access observations associate an opaque credential context with an observed object. No credential secret is part of the persisted schema.

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

### 8. Offline Findings Flow

The complete operator workflow is:

1. scan authorized SMB targets
2. persist scan state, findings, material, and provenance in local SQLite
3. finish or stop the scan
4. reopen the database with `snablr find` or `snablr find --db PATH`
5. review categories, logical discoveries, Details, and source observations

Finder opens the database read-only and never reconnects to SMB. SQLite files
are assessment-sensitive artifacts: protect them and any exports that contain
raw evidence.

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
  - progress, scan database, HTML reporting, and offline rule testing are first-class features
