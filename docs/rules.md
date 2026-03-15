# Rules

Snablr uses YAML rule files so operators can maintain detections without changing Go code. The rule system is designed to be readable, testable, and easy to tune for real environments.

Rule files live under:

- `configs/rules/default/`
- `configs/rules/custom/`

Snablr loads every `.yml` and `.yaml` file in the configured rule directories.

## Rule File Structure

Each rule file contains top-level metadata plus a `rules` list.

Example:

```yaml
version: 1
name: defensive-content
description: Defensive content review for secret indicators.
rules:
  - id: content.password_assignment_indicators
    name: Password Assignment Indicators
    description: Detect simple password assignments in config and text files.
    type: content
    pattern: '(?m)(password|passwd|pwd|secret)\s*[:=]\s*["'']?[^"''\s;]+'
    case_sensitive: false
    severity: high
    confidence: medium
    explanation: This pattern may indicate a hardcoded credential in a configuration-style file.
    remediation: Move credentials to a secure secret store or environment-specific secret injection path.
    tags: [passwords, secrets, generic]
    category: credentials
    enabled: true
    include_paths: []
    exclude_paths: [node_modules, vendor, winsxs]
    file_extensions: [.txt, .conf, .config, .ini, .yaml, .yml, .json, .xml]
    max_file_size: 524288
    action: report
```

## Rule Schema

Important fields:

- `id`
  Globally unique rule identifier.

- `name`
  Human-readable display name.

- `description`
  Short description of what the rule is meant to detect.

- `type`
  Match surface.
  Supported values:
  - `content`
  - `filename`
  - `extension`

- `pattern`
  Regular expression to apply to the selected surface.

- `case_sensitive`
  Controls regex case sensitivity.

- `severity`
  Analyst-facing importance.
  Supported values:
  - `low`
  - `medium`
  - `high`
  - `critical`

- `confidence`
  Optional confidence hint for the operator.
  Supported values:
  - `low`
  - `medium`
  - `high`

- `explanation`
  Optional plain-English explanation shown in findings and reports.

- `remediation`
  Optional plain-English remediation guidance shown in findings and reports.

- `tags`
  Free-form labels used for grouping and filtering.

- `category`
  Broad grouping used in reports and triage.

- `enabled`
  Controls whether the rule is active.

- `include_paths`
  Only apply the rule when the path matches one of these prefixes or fragments.

- `exclude_paths`
  Skip the rule when the path matches one of these prefixes or fragments.

- `file_extensions`
  Restrict the rule to specific file extensions.

- `max_file_size`
  Do not apply the rule to files larger than this many bytes.

- `action`
  Controls how the match is treated.
  Supported values:
  - `report`
  - `skip`
  - `prioritize`

## Rule Types

### `content`

The regex is applied to file contents.

Use this for:

- hardcoded password or token indicators
- key or certificate block headers
- connection string patterns
- conservative PII or identifier review

### `filename`

The regex is applied to the basename of the file.

Use this for:

- suspicious backup or export names
- password manager artifacts
- cloud credential filenames
- deployment answer files

### `extension`

The regex is applied to the normalized extension, such as `.xml` or `.pem`.

Use this for:

- key and certificate material
- config files
- script-heavy file types
- export or database-related formats

## Action Semantics

### `report`

Emit a finding when the rule matches.

### `prioritize`

Emit a finding and treat it as especially relevant for review.

### `skip`

Use the rule as an exclusion rule. Matching files or paths are skipped.

## Rule Categories

Categories are free-form strings, but they should stay stable so outputs remain predictable.

Common default categories include:

- `credentials`
- `cloud`
- `crypto`
- `deployment`
- `configuration`
- `directory-services`
- `business-sensitive`
- `exclusion`

The default defensive rule pack is split across:

- `content.yml`
- `filenames.yml`
- `extensions.yml`
- `excludes.yml`
- `pii.yml`
- `infrastructure.yml`

These default packs are intentionally tuned for defensive discovery and remediation review rather than extraction or exploitation.

## Confidence, Explanation, And Remediation

Snablr supports three optional explainability fields:

- `confidence`
- `explanation`
- `remediation`

These fields are useful because they improve findings without changing detection behavior.

Example:

```yaml
confidence: medium
explanation: This pattern may indicate a hardcoded credential in a configuration file.
remediation: Move credentials to a secure secret manager or environment variable.
```

How they are used:

- console output
  - keeps them concise, primarily as confidence and short rule notes

- JSON output
  - includes them fully as structured finding fields

- HTML report
  - displays them directly in each finding for triage and remediation review

Rules that do not include these fields still work normally.

## Validation

Snablr validates rules before scanning or test execution.

Validation checks include:

- missing required fields
- invalid rule type
- invalid severity
- invalid confidence
- invalid action
- bad regex patterns
- duplicate IDs
- unsupported YAML fields

Validate rules with:

```bash
./bin/snablr rules validate --config configs/config.yaml
```

## Testing Rules

### Test One Rule File

```bash
./bin/snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/passwords/sample.conf \
  --verbose
```

### Test A Rule Directory

```bash
./bin/snablr rules test-dir \
  --rules configs/rules/default \
  --fixtures testdata/rules/fixtures \
  --verbose
```

Exit codes:

- `0` no matches
- `1` validation or execution error
- `2` one or more matches

This makes rule testing suitable for CI pipelines.

## Tuning Rules

Rule tuning should usually happen in this order:

1. narrow `exclude_paths`
2. narrow `file_extensions`
3. add `include_paths`
4. disable noisy rules
5. only then change the regex

Recommended guidance:

- keep shipped defaults understandable
- move organization-specific logic into custom rules
- prefer several focused rules over one very broad rule
- keep broad or noisy defaults disabled until you need them

Examples of noisy-but-useful patterns:

- generic token assignment rules
- broad business-sensitive filename rules
- conservative PII-like content patterns

See also:

- `docs/tuning.md`
- `docs/workflows.md`

## Custom Rules

The recommended approach is:

1. keep `configs/rules/default/` as the shipped baseline
2. add local rules under `configs/rules/custom/`
3. validate and test those rules before use

Example custom rule:

```yaml
version: 1
name: local-rules
description: Local organization-specific review rules.
rules:
  - id: filename.local_sensitive_project_docs
    name: Local Sensitive Project Docs
    description: Detect local naming for sensitive project deliverables.
    type: filename
    pattern: '(?i)(project-atlas|board-review|remediation-plan)'
    case_sensitive: false
    severity: medium
    confidence: medium
    explanation: These filenames may indicate internal reporting or remediation material.
    remediation: Review whether these files belong on a broad-access share and tighten access if needed.
    tags: [local, example, business-sensitive]
    category: business-sensitive
    enabled: true
    include_paths: []
    exclude_paths: [archive, temp, cache]
    file_extensions: [.docx, .pdf, .xlsx, .csv, .txt]
    max_file_size: 0
    action: report
```

The examples directory contains a similar sample rule you can copy and adapt.
