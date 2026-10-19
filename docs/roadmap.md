# Roadmap

These items track future work; authenticated share listing is implemented.

## Permanent Scope Restriction

Snablr is a discovery, classification, evidence-extraction, correlation, and
reporting tool. It must never become a hash-cracking or credential-decryption
tool. Development must not add dictionary attacks, brute-force recovery,
online password guessing, NTLM-to-plaintext recovery, SCCM blob decryption,
DPAPI decryption, key-based secret recovery, or integrations with external
cracking/decryption tools. Supported work may identify validated encrypted
artifacts and preserve their original material, but must not claim plaintext
recovery without actual plaintext extraction.

## Development Sequence

1. Intelligent SQLite Resume/Rescan — implemented and live-validated.
2. Persistent Skip Folder / Skip Share — current implementation priority.
3. Expanded Recursive SMB Lab Seeding.
4. Kali Deployment and Manual Operator Acceptance.
5. CLI Command Audit, Help Redesign, and Developer Mode.
6. NTLM/SCCM Hash Detection and Rule Expansion.
7. Larger future Snablr development work.

## Intelligent Resume/Rescan (implemented and validated)

Resume and compatible completed-target/share reuse must remain SQLite-backed and
must distinguish complete coverage from interrupted, failed, timed-out, or
otherwise unavailable work. `--force-rescan` provides an explicit fresh scan
without discarding historical evidence, and `--resume --force-rescan` remains a
clear invalid combination. The next implementation step is persistent Skip
Folder and Skip Share behavior, using the existing scheduler cooperatively and
keeping both exclusions distinct from Alt-L deferred-share scheduling.

All scope exclusions and completion decisions must use authoritative SQLite
state, preserve WAL recovery and completed-file reuse, and avoid detached SMB
recovery or unsafe cancellation. The implementation must retain existing
search, bookmarks, queue, evidence, credential, report, and interruption
behavior.

## Expanded Recursive Lab Seeding (mandatory pre-acceptance milestone)

After Skip Folder and Skip Share are implemented, and before final manual TUI
acceptance, create a substantial deterministic, independently synthetic SMB
corpus. This is a validation milestone, not a reason to redesign the scanner;
seeding must not begin until the scope-exclusion implementation is ready.

The generic seeder should be idempotent and configurable for lab capacity,
initially targeting approximately 10,000–30,000 files across multiple dedicated
test shares. It must provide:

- A 10–15-level deep recursive tree with multiple branches, mixed extensions,
  synthetic configuration files, benign files, and known evidence fixtures.
- A wide tree with hundreds of sibling directories, nested content, and enough
  files to exercise progress, traversal ordering, and scheduler transitions.
- A deterministic `SkipFolder-Test/` layout containing `1/2/3/` with
  `Nested-A/`, `Nested-B/`, and `Nested-C/`, plus distinct `1/2/30/`,
  `1/2/4/`, `1/5/`, and `OtherBranch/` paths, all populated with synthetic
  files for boundary and normalization checks.
- Multiple populated shares for testing Skip Share separately from Alt-L
  defer-and-return behavior.
- A resume/rescan corpus suitable for repeated compatible scans, interruption
  and continuation, hard-kill/WAL recovery, completed-file reuse,
  `--force-rescan`, controlled synthetic changes, and persisted exclusions.
- Positive and negative evidence fixtures covering existing Snablr rule areas:
  PowerShell and shell assignments, unattend/CustomSettings passwords,
  connection strings, ZIP/OOXML/SQLite artifacts, SSH/VPN/AWS credentials,
  browser/Windows credential stores, backups, correlations, masked or
  placeholder values, and benign lookalikes. Fixtures must remain synthetic,
  high-signal, and free of unnecessary duplicate findings.

The seeder must produce a versioned local or otherwise untracked manifest with
fixture version, share and relative-path inventory, directory/file counts,
expected coverage, evidence positives and negative controls, and expected
skip-subtree behavior. Actual lab topology, credentials, manifests, reports,
databases, outputs, and other machine-specific data must remain outside Git.
Before manual acceptance, validate remote inventory and access, synchronize the
exact tested revision to Kali, build there, verify the binary's commit, verify
the seeded inventory, run bounded smoke tests, and leave the environment ready
for operator-driven TUI testing.

Hash detection remains a later phase after resume/skip validation, recursive
seeding, and manual acceptance; it is not part of the current implementation.

## CLI Command Audit, Help Redesign, and Developer Mode (planned)

This milestone follows recursive lab seeding and operator acceptance. It must
not interrupt the current Skip Folder / Skip Share work or alter scanner
behavior while the CLI is being audited. The goal is a clean, professional
operator interface without deleting the advanced capabilities already exposed.

### Command audit

Audit the actual implementation and usage of `scan`, `discover`, `rules`,
`diff`, `benchmark`, `eval`, `version`, and `help`. For each command, document
its purpose, real usage, operator/developer audience, overlap, help visibility,
developer-mode suitability, and automation compatibility. Do not assume that
everything except `scan` is developer-only: `discover`, `rules`, and `diff`
may remain ordinary operator commands where their workflows justify it.

The initial proposal is to keep a concise `snablr`, `snablr scan`,
`snablr version`, and `snablr help` experience while investigating a
`snablr dev` namespace. Candidate developer commands include
`dev benchmark`, `dev eval`, `dev rules`, `dev discover`, and `dev diagnostics`,
but only existing functionality with a clear purpose may be moved. Do not add
placeholder commands or speculative diagnostics. Preserve legacy command paths
as functional aliases when needed, hiding them from short help rather than
silently breaking scripts; command moves and removals require operator review.

### Developer namespace and flag classification

`snablr dev` is a presentation namespace, not a second scanner, persistence
backend, permission path, or authentication bypass. Advanced authentication,
scope selection, resume, and rescan options remain legitimate operator tools
unless the audit demonstrates otherwise.

Classify every current `scan` flag into:

- Common operator flags: targets, credentials, domain, shares, resume,
  force-rescan, reports, and TUI selection.
- Advanced operator flags: Kerberos/LDAP overrides, profiles, path/share
  exclusions, worker and timeout controls, and advanced reporting.
- Developer/diagnostic flags: validation mode, manifest verification, and
  internal development controls.
- Specialized inspection flags: WIM extraction limits, image counts, and
  member-size controls.

Do not remove WIM functionality or change defaults. Investigate whether WIM
options should primarily be documented in YAML while retaining compatible CLI
overrides.

### Help hierarchy and presentation

Design and test distinct help levels:

- `snablr -h`: compact banner, accurate version/build metadata, short product
  description, common commands, minimal examples, and pointers to advanced and
  developer help.
- `snablr scan -h`: common scanning, authentication, scope, resume/rescan,
  output/report options, and a small set of useful examples.
- `snablr scan --help-advanced`: the complete advanced operator flag reference.
- `snablr dev -h` and `snablr dev <command> -h`: supported developer tools only.

Retain the recognizable ASCII banner while improving spacing, alignment,
grouping, and concise explanations. Use restrained green headings, cyan/blue
command and flag names, neutral descriptions, and yellow warnings only when
meaningful. Honor `--no-color` and `NO_COLOR`; never emit ANSI escapes when
help is redirected or piped. The layout must remain readable in narrow
terminals, SSH, and tmux sessions without adding unnecessary rendering
dependencies.

### Version, compatibility, and validation

Audit version metadata so operators can identify the actual executable with
version, short commit hash, and build date when available. Development builds
must not be presented as official releases. Reuse existing build metadata where
possible instead of changing the versioning system unnecessarily.

Preserve existing commands, flags, scan defaults, authentication handling,
SQLite persistence, scheduling, resume behavior, output formats, and exit-code
semantics. Before implementation, document any deprecation or compatibility
impact for approval.

The implementation stage must test normal, scan, advanced, developer, alias,
invalid-argument, exit-code, color, `NO_COLOR`, redirected, piped, narrow,
and version/help flows. Run `make test`, `make build`, `make lint`, and the
Windows cross-build. Deploy the exact committed revision to the authorized
Kali environment, build directly there, verify the deployed commit and
`/home/kali/Snablr/bin/snablr`, and leave the actual help output ready for
manual operator review. This milestone must not weaken scanner permissions or
credential safeguards.

## Authenticated Share Listing (implemented)

`--list-shares` authenticates using the selected password, NTLM-hash, or
Kerberos identity, tests each candidate with tree connect plus root directory
listing, and prints only readable filesystem shares for that identity before
exiting. It does not start a normal file scan or persist scan state.

## SECURITY + SYSTEM Secrets (implemented)

Modern Vista-and-later `SECURITY` + `SYSTEM` pairs are analyzed with bounded
PolEKList AES LSA-key derivation, structured LSA-secret metadata, and cached
domain-material discovery. Raw secret bytes are not returned in findings or
reports. Legacy pre-Vista LSA protection remains deferred.

## NTDS.DIT + SYSTEM (implemented)

Modern read-only NTDS.DIT + SYSTEM analysis now recovers current domain NT hash
metadata from origin-safe loose and WIM pairs. Password history,
supplementalCredentials/Kerberos keys, and legacy database formats remain
deferred.

## Post-scan Credential Analysis (in progress)

The shared post-scan model classifies extracted credential material as
confirmed or review without narrowing discovery recall. Confirmed records carry
offline structural or cryptographic validation provenance; uncertain material
remains available under `Potential Credential Material — Review`. Raw values are
reserved for the explicit highly-sensitive `--creds-out` export, and Snablr
never tests recovered credentials against live systems. Password history,
supplementalCredentials/Kerberos keys, and legacy pre-Vista SECURITY remain
deferred.
