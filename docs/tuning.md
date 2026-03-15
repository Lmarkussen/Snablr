# Rule Tuning Guide

Snablr ships with a defensive default rule pack that is meant to be useful out of the box without overwhelming operators. Real environments vary, so tuning is expected.

This guide covers the fastest ways to improve signal quality while keeping the default rules intact.

## Tune Filename Keywords

Broad filename keywords can become noisy quickly because naming conventions vary across teams and business units.

Recommended approach:

- keep the shipped defaults focused on high-signal names
- add organization-specific terms in `configs/rules/custom/`
- prefer several small rules over one large catch-all keyword list

Example custom filename rule:

```yaml
version: 1
name: org-filenames
description: Organization-specific filename indicators.
rules:
  - id: filename.org_finance_exports
    name: Organization Finance Export Filenames
    description: Detect local naming used for finance and reporting exports.
    type: filename
    pattern: '(?i)(quarter-close|finance-master|hr-master-export)'
    case_sensitive: false
    severity: high
    tags: [organization, business-data, filenames]
    category: business-data
    enabled: true
    include_paths: []
    exclude_paths: [cache, temp, tmp]
    file_extensions: [.csv, .xlsx, .pdf]
    max_file_size: 0
    action: report
```

Good practice:

- add local project names, department names, export labels, and system nicknames in custom rules
- keep generic words like `report`, `backup`, `copy`, and `client` disabled unless paired with stronger context

## Tune Include And Exclude Paths

The quickest way to reduce noise is usually path tuning rather than regex tuning.

Use `exclude_paths` to suppress low-value content such as:

- dependency trees
- build output
- caches
- temp directories
- generated documentation
- exported application bundles

Use `include_paths` when a rule only makes sense in a narrow area, such as:

- `policies`
- `finance`
- `hr`
- `backups`
- `deploy`
- `scripts`

Example:

```yaml
include_paths: [finance, exports]
exclude_paths: [cache, temp, archive]
```

This is usually easier to maintain than making the regex more complex.

## Narrow File Extensions

If a rule is useful in principle but too broad in practice, reduce the number of file types it evaluates.

Examples:

- content rules for secrets: limit to `.env`, `.ini`, `.json`, `.yaml`, `.yml`, `.xml`, `.config`
- filename rules for business exports: limit to `.csv`, `.tsv`, `.xls`, `.xlsx`, `.pdf`
- infrastructure rules: limit to `.tf`, `.tfvars`, `.json`, `.yaml`, `.yml`, `.env`

Example:

```yaml
file_extensions: [.env, .json, .yaml, .yml]
```

This is usually the safest first tuning step for noisy content rules.

## Reduce False Positives

Use this order of operations:

1. disable obviously noisy rules
2. narrow `file_extensions`
3. add `include_paths`
4. expand `exclude_paths`
5. only then adjust the regex

Broad rules that commonly need tuning first:

- token variable detections
- generic archive and export filename rules
- number-pattern PII rules
- CI/CD variable name rules
- generic administration script naming rules

If a rule is still useful but too noisy, keep it available and set:

```yaml
enabled: false
```

That preserves it for future use without removing it from the pack.

## Use A Custom Rules Directory

Do not edit the default pack unless you want to maintain a fork of it.

Preferred approach:

1. leave `configs/rules/default/` as the vendor-style baseline
2. add your own files under `configs/rules/custom/`
3. point Snablr at both directories through configuration

Example config:

```yaml
rules_directory:
  - configs/rules/default
  - configs/rules/custom
```

This lets you:

- keep defaults easy to update
- disable noisy defaults locally
- add team-specific keywords and paths
- test custom rules in CI without modifying the shipped pack

## Validate And Test After Tuning

Validate rules:

```bash
snablr rules validate --config configs/config.yaml
```

Test a single rule file:

```bash
snablr rules test --rule configs/rules/custom/finance.yml --input testdata/rules/fixtures/business/employee-payroll-export.csv
```

Test a full directory of rules against fixtures:

```bash
snablr rules test-dir --rules configs/rules/default --fixtures testdata/rules/fixtures --verbose
```

Tune in small steps. If you disable a rule, document why. If you add local keywords, keep them specific enough that another operator can understand why a file matched.
