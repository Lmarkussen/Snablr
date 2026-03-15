# Snablr Performance Notes

Snablr includes a few default optimizations intended for larger environments with many hosts, large shares, and high file counts.

## What Changed

- Adaptive worker scaling:
  - `worker_count: 0` now means "auto".
  - Auto mode resolves to a CPU-based worker count, capped to stay readable and predictable.
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

- Leave `worker_count` at `0` unless you have a reason to cap it manually.
- Keep `max_file_size` conservative for very large environments.
- Use `--share`, `--exclude-share`, `--path`, `--exclude-path`, and `--max-depth` to reduce the search space early.
- Use checkpoints for long-running scans so interrupted runs can resume without redoing completed work.

## Tradeoffs

- File priority is now applied in bounded batches rather than after fully materializing a whole share.
- This reduces memory pressure substantially while preserving priority ordering within each batch.
