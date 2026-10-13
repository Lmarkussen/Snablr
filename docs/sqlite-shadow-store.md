# SQLite Shadow Scan Store

Phase 1 adds an optional SQLite shadow copy of scan state. Configure
`scan.sqlite_state_file` or pass `--sqlite-state-file <path>` to enable it.
The JSON checkpoint and incremental `inventory.json` remain authoritative for
all default resume and reuse decisions. SQLite resume is available only through
the explicit experimental migration switch described below.

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

If SQLite initialization or persistence fails, the shadow store becomes
unhealthy and stops accepting writes. The scan, JSON checkpoint, and
incremental inventory continue under their existing behavior. Shadow failures
are not resume decisions.

The store tests exercise order-independent logical snapshots, partial and
retryable work, archive/WIM provenance, findings, credentials, interruption,
transaction rollback/reopen, restrictive permissions, and a synthetic 100,000
file write workload.

## Experimental SQLite resume

Phase 2 adds an opt-in migration path: pass `--sqlite-resume` together with
`--resume` and the same `--sqlite-state-file` used by the interrupted scan.
Snablr validates the existing schema and scan metadata, reconstructs logical
checkpoint/inventory state, and resumes only compatible completed work. Rows
that were pending, failed, partial, or invalidated by a semantics fingerprint
change remain eligible for inspection. Findings and credentials from completed
work are rehydrated through the normal output sink so resumed results remain
idempotent.

This mode is temporary development functionality. JSON checkpointing remains
the authoritative default and remains the fallback when SQLite shadow state is
unavailable. SQLite state and reports can contain sensitive recovered
credentials; protect both files and their parent directories.

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
