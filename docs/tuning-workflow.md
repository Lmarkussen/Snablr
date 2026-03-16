# Tuning Workflow

Snablr tuning should be deliberate and repeatable. The goal is to improve useful findings and reduce noisy ones using authorized datasets.

## Recommended Workflow

1. Prepare an authorized dataset.
2. Label expected findings for that dataset.
3. Run `snablr eval`.
4. Review misses, noisy findings, and duplicate findings.
5. Tune rules.
6. Run `snablr benchmark`.
7. Compare the new benchmark and evaluation reports with the previous run.

## Dataset Sources

Use one of these:

- a synthetic seeded lab dataset
- a curated internal test corpus that you are explicitly allowed to use
- a sanitized export of representative files

Do not use unapproved production data for routine tuning.

## Evaluation Loop

Run evaluation:

```bash
snablr eval --dataset examples/eval/dataset --labels examples/eval/labels.yaml --out eval.json
```

Review:

- missed findings
- noisy findings
- duplicate findings
- noisy rule candidates
- missed rule candidates

Useful interpretation:

- missed findings suggest missing or over-constrained rules
- noisy findings suggest broad patterns or weak filename keywords
- duplicate findings suggest overlapping rules that should be merged or correlated better

## Benchmark Loop

Run benchmarking:

```bash
snablr benchmark --config examples/eval/benchmark.yaml --out benchmark.json
```

Review:

- duration
- time to first finding
- files visited
- files read
- grouped findings
- high-confidence findings

## What to Tune First

Usually tune in this order:

1. noisy filename keywords
2. broad include paths
3. broad file extension scopes
4. content rules that trigger on common config boilerplate
5. max file size or max read size for large corpora

## Safe Rule Tuning Tips

- prefer several focused rules over one broad regex
- keep high-noise rules disabled by default until you have labels to support them
- narrow `file_extensions` before broadening content patterns
- add organization-specific filename keywords in custom rules instead of editing defaults
- keep severity and confidence aligned with how strong the signal really is

## Suggested Change Log

For each tuning pass, record:

- what changed
- why it changed
- expected impact
- benchmark delta
- evaluation delta

That history makes it much easier to understand whether a rule change improved signal or only moved noise around.
