# Snablr Performance Notes

Snablr includes a few default optimizations intended for larger environments with many hosts, large shares, and high file counts.

## What Changed

- Safe worker scaling:
  - `worker_count` defaults to `15` to avoid overloading SMB/file servers.
  - Higher values may improve scan speed but can put significant load on file servers.
  - `worker_count: 0` still means adaptive CPU-based scaling when explicitly configured.
  - Operators can still set an explicit `worker_count` to pin concurrency.

- Reduced unnecessary content reads:
  - The scanner caches rule sets by type instead of re-fetching them for every file.
  - Content reads are skipped early when the loaded content rules are extension-scoped and the file extension cannot match any content rule.
  - Max-size limits still apply before reads.

- Lower memory pressure during share walks:
  - Share enumeration no longer accumulates an entire share's file list in memory before planning.
  - Files are planned and queued in bounded batches.
  - This keeps memory growth flatter on very large shares.

- Priority-aware batching:
  - Each batch is still passed through the planner before queueing.
  - Higher-value extensions and paths are queued earlier within each batch.

## Operational Guidance

- Leave `worker_count` at the default `15` in production unless you have measured capacity to raise it.
- Keep `max_file_size` conservative for very large environments.
- Use `--share`, `--exclude-share`, `--path`, `--exclude-path`, and `--max-depth` to reduce the search space early.
- Use checkpoints for long-running scans so interrupted runs can resume without redoing completed work.

## Tradeoffs

- File priority is now applied in bounded batches rather than after fully materializing a whole share.
- This reduces memory pressure substantially while preserving priority ordering within each batch.
