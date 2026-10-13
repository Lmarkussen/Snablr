# SQLite Scan State (Phase 3)

Phase 3 makes SQLite the authoritative scan-state backend for normal scans.
Snablr creates `snablr.db` in the configured state/output workspace (or uses
the explicit `scan.sqlite_state_file`/`--sqlite-state-file` override). The
database is required for correctness during an SQLite-authoritative scan; a
runtime write failure stops new work and exits non-zero rather than silently
switching persistence backends.

The legacy JSON checkpoint and incremental inventory remain available only as
an explicit compatibility path with `--legacy-json`. This migration switch is
temporary and is retained for recovery and parity testing; it is not consulted
by SQLite-authoritative resume.

The database uses schema version 1 and records scan metadata, target/share
completion, file work states, credential-context access observations, archive
and WIM member identity, visible findings, credential candidates, and
correlation payloads. It does not store whole remote files. Values in the
database can include recovered credentials, so the database directory, main
file, WAL, and SHM files are treated as sensitive and restricted to mode 0600.

Writes use a bounded queue and batched transactions. WAL allows a future
reader to observe a scan while it is running. `foreign_keys=ON` protects
relational integrity, `busy_timeout=5000` avoids transient reader/writer
failures, and `synchronous=NORMAL` is used with WAL because committed batches
remain transactionally consistent while avoiding a full fsync for every batch.

If SQLite initialization or persistence fails, the authoritative store becomes
unhealthy, cancels scheduling, preserves committed transactions, finalizes
what it safely can, and reports a non-zero failure. There is no mid-scan JSON
fallback because changing authorities would make resume correctness unknowable.

The store tests exercise order-independent logical snapshots, partial and
retryable work, archive/WIM provenance, findings, credentials, interruption,
transaction rollback/reopen, restrictive permissions, and a synthetic 100,000
file write workload.

## SQLite resume

Pass `--resume` to reopen the latest scan in the selected SQLite database.
`--sqlite-resume` remains accepted as a temporary compatibility alias, but is
not required. Snablr validates the schema, scan metadata, integrity, and
semantics fingerprint before resuming. Rows that were pending, failed,
partial, or invalidated by a semantics change remain eligible for inspection.
Findings and credentials from completed work are replayed through the normal
output sink with stable identities, so reopening does not duplicate results.

For migration testing, `--legacy-json --checkpoint-file <path>` selects the
old JSON authority explicitly. SQLite state and reports can contain sensitive
recovered credentials; protect both files and their parent directories.

## Phase 2.5 replay semantics

The migration resume path uses SQLite as a lazy decision index: target/share
completion and file identity/status are queried by indexed lookup, rather than
loading the complete file inventory into Go memory. The normal scan then
re-enumerates shares and schedules only files whose persisted status is not
compatible with the current metadata and semantics fingerprint.

- Files: `RESTORE` resume decisions from SQLite; incomplete, failed, partial,
  and semantics-invalidated rows are eligible for normal scanner work.
- Archive/WIM members: `HYBRID`. Completed outer containers retain their
  persisted member provenance for replay/report parity. Incomplete or failed
  outer-container inspection is recomputed by the existing outer-file scanner;
  members are never independently detached or reopened.
- Findings: `REPLAY` persisted findings through the normal sink, with the
  existing logical deduplication path handling observations crossing the
  interruption boundary.
- Credentials: `REPLAY` persisted candidate payloads, including actual values,
  through the normal credential sink. SQLite persistence never logs them.
- Correlations: `RECOMPUTE`. Correlation edges are keyed/upserted in SQLite and
  report correlation is deterministic and idempotent; persisted edges are
  inspection/parity evidence, not a second report source.

The opt-in million-row measurement is run with
`SNABLR_SQLITE_MILLION=1`; it is excluded from ordinary CI because it is a
performance measurement rather than a fragile pass/fail threshold.
