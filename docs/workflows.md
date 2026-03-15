# Snablr Workflows

This guide collects a few practical workflows that map directly to how Snablr is designed to be used in real environments.

## Run A Direct Host Scan

Use this when you already know the host or small host list you want to review.

Example:

```bash
./bin/snablr scan \
  --targets 172.16.0.90,172.16.0.91 \
  --user 'DOMAIN\user' \
  --pass 'REPLACE_ME' \
  --output-format all \
  --json-out results/direct.json \
  --html-out results/direct.html
```

Good fit for:

- validating SMB access
- checking a single file server
- quick triage before a broader run

See also:

- `examples/config.basic.yaml`

## Run A Domain-Aware Scan

Use this when you want Snablr to discover likely targets from Active Directory.

Example:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml
```

Expected behavior:

- LDAP discovery loads candidate hosts when explicit targets are not provided
- reachability checks reduce wasted SMB connections
- AD shares remain high priority
- DFS-linked shares can be added when DFS discovery is enabled

Good fit for:

- broad enterprise hygiene reviews
- identifying exposed share content across many hosts
- generating a full report set for review and remediation

## Test Custom Rules

Before using custom rules in a live scan, validate and test them offline.

Validate:

```bash
./bin/snablr rules validate --config configs/config.yaml
```

Test a single rule file:

```bash
./bin/snablr rules test \
  --rule examples/rules/custom/example.yml \
  --input testdata/rules/fixtures/business/employee-payroll-export.csv \
  --verbose
```

Test a directory of rules:

```bash
./bin/snablr rules test-dir \
  --rules examples/rules/custom \
  --fixtures testdata/rules/fixtures \
  --verbose
```

Good fit for:

- CI validation
- noise reduction before rollout
- organization-specific keyword tuning

## Resume A Scan

Use checkpoints for long-running scans or unstable environments.

Example:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --checkpoint-file state/domain-scan.json \
  --resume
```

Recommended workflow:

1. start with checkpointing enabled
2. let the scan run until completion or time limit
3. rerun with `--resume` to continue without rescanning completed work

Good fit for:

- large environments
- constrained change windows
- unreliable network paths

## Review The HTML Report

The HTML report is meant for post-scan review and handoff.

Typical flow:

1. open `report.html` in a browser
2. review the summary cards and severity counts
3. open the highest-severity categories first
4. filter by host, share, rule, or tag
5. export or reference the Markdown summary for notes or tickets

Recommended command:

```bash
./bin/snablr scan \
  --config examples/config.domain.yaml \
  --output-format all \
  --json-out output/domain/results.json \
  --html-out output/domain/report.html \
  --csv-out output/domain/findings.csv \
  --md-out output/domain/summary.md
```

## Tune Noisy Rules

Start with path and extension tuning before changing regexes.

Recommended order:

1. disable obviously noisy rules
2. narrow `file_extensions`
3. add `include_paths`
4. expand `exclude_paths`
5. only then adjust patterns

Common tuning workflow:

```bash
./bin/snablr rules validate --config configs/config.yaml
./bin/snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose
```

If a default rule is useful in principle but too broad for your environment:

- copy it into `examples/rules/custom/` or `configs/rules/custom/`
- change the rule ID
- narrow the scope
- retest it against fixtures

See also:

- `docs/rules.md`
- `docs/tuning.md`
