# Benchmarking

Snablr benchmarking is meant for authorized local datasets. It measures how quickly Snablr scans a corpus and how much signal it produces, so rule and engine changes can be compared over time.

## What a Benchmark Captures

Each benchmark run records:

- scan duration
- time to first finding
- files visited
- files read
- matches found
- grouped findings
- high-confidence findings
- finding counts by category
- finding counts by severity
- finding counts by rule

The benchmark runner uses the normal Snablr rule engine on a local directory. It does not use SMB or LDAP.

## Example

```bash
snablr benchmark --config examples/eval/benchmark.yaml --out benchmark.json
```

Example benchmark config:

```yaml
name: example-lab-benchmark
dataset: examples/eval/dataset
snablr_config: configs/config.yaml
worker_count: 4
max_file_size: 1048576
max_read_bytes: 262144
snippet_bytes: 120
log_level: info
```

## Reading the Results

The benchmark JSON report is useful for comparing runs before and after tuning:

- lower `duration_ms` means faster scans
- lower `time_to_first_finding_ms` means relevant files are surfaced earlier
- `files_read` should not grow unnecessarily
- `grouped_findings` should stay stable or improve after rule cleanup
- `high_confidence_findings` should ideally increase without a large rise in noisy findings during evaluation

## Comparing Runs

Store benchmark reports from multiple runs and compare:

- duration
- files read
- grouped findings
- high-confidence findings
- top rules or categories contributing findings

Good tuning usually reduces:

- unnecessary file reads
- broad noisy matches
- time to first relevant finding

without reducing:

- expected grouped findings
- high-confidence findings on known-good datasets
