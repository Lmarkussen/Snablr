# Rules

Snablr uses YAML rule files so operators can add, remove, disable, test, and tune detections without recompiling the application.

Rule files live under:

- `configs/rules/default/`
- `configs/rules/custom/`

Snablr loads every `.yml` and `.yaml` file in the configured rule directories.

## Rule System Overview

The rule engine is intentionally split from SMB enumeration and scan orchestration.

That separation means:

- the SMB layer only provides file metadata and content
- the scanner only evaluates metadata and content against loaded rules
- the rule pack can evolve independently from Go code

Snablr supports three rule types:

- `content`
- `filename`
- `extension`

It also supports:

- severity
- confidence
- tags
- categories
- include/exclude path logic
- file extension filters
- maximum file size filters
- enable/disable without recompiling

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
  Globally unique rule ID
- `name`
  Human-readable display name
- `description`
  Short purpose statement
- `type`
  Matching surface: `content`, `filename`, or `extension`
- `pattern`
  Regular expression applied to the selected surface
- `case_sensitive`
  Controls regex case sensitivity
- `severity`
  Analyst-facing importance: `low`, `medium`, `high`, `critical`
- `confidence`
  Optional signal hint: `low`, `medium`, `high`
- `explanation`
  Optional plain-English reason shown in findings and reports
- `remediation`
  Optional plain-English remediation guidance shown in findings and reports
- `tags`
  Free-form labels used for grouping and filtering
- `category`
  Stable grouping used by reports and summaries
- `enabled`
  Controls whether the rule is active
- `include_paths`
  Restrict the rule to matching paths
- `exclude_paths`
  Skip the rule for matching paths
- `file_extensions`
  Restrict the rule to certain extensions
- `max_file_size`
  Skip files larger than this many bytes for the rule
- `action`
  `report`, `skip`, or `prioritize`

## How Matching Works

### `content`

The regex is applied to file contents.

Use it for:

- password assignments
- token or secret assignments
- connection strings
- key or certificate block headers
- conservative review indicators in config-like files

### `filename`

The regex is applied to the basename of the file.

Use it for:

- credentials or secret keywords
- backup or export naming
- deployment answer files
- password-manager artifacts
- business-sensitive filenames

### `extension`

The regex is applied to the normalized file extension, for example `.xml` or `.pem`.

Use it for:

- config file types
- script-heavy file types
- key or certificate material
- export or database file types

## Action Semantics

### `report`

Emit a finding when the rule matches.

### `prioritize`

Emit a finding and mark the finding as especially relevant for review.

### `skip`

Treat the rule as an exclusion rule so matching files or paths are skipped.

## Default Defensive Rule Pack

The shipped default pack is organized into:

- `content.yml`
- `filenames.yml`
- `extensions.yml`
- `excludes.yml`
- `pii.yml`
- `infrastructure.yml`

Broad categories covered by the defaults:

- hardcoded secret indicators
- generic credential exposure indicators
- private key and certificate material indicators
- cloud and infrastructure configuration indicators
- database connection string indicators
- unattended deployment and answer file indicators
- backup and export naming indicators
- password-manager artifact indicators
- PII and business-sensitive review indicators
- AD policy and administration review indicators
- noisy exclusion rules for low-value media, binaries, caches, and temp paths

## Confidence, Explanation, And Remediation

Snablr supports three optional explainability fields:

- `confidence`
- `explanation`
- `remediation`

Example:

```yaml
confidence: medium
explanation: This pattern may indicate a hardcoded credential in a configuration file.
remediation: Move credentials to a secure secret manager or environment variable.
```

How they appear:

- console
  concise confidence and rule note output
- JSON
  structured finding fields for automation
- HTML
  visible explanation and remediation guidance in each finding group

Rules without these fields still work normally.

## Validation

Snablr validates rules before scanning or rule testing.

Validation checks include:

- missing required fields
- invalid type, severity, confidence, or action values
- bad regex patterns
- duplicate IDs
- unsupported YAML fields

Validate the active rule set:

```bash
snablr rules validate --config configs/config.yaml
```

## Testing Rules

### Test One Rule File Against One Fixture

```bash
snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/content/password-assignment.conf \
  --verbose
```

### Test A Rule Directory Against Many Fixtures

```bash
snablr rules test-dir \
  --rules configs/rules/default \
  --fixtures testdata/rules/fixtures \
  --verbose
```

Exit codes:

- `0` no matches
- `1` validation or execution error
- `2` one or more matches

That makes the rule testing path usable in CI pipelines and local tuning workflows.

## Tuning Rules

Recommended tuning order:

1. narrow `exclude_paths`
2. narrow `file_extensions`
3. add `include_paths`
4. disable noisy rules
5. only then widen or rewrite regexes

Guidance:

- keep default packs readable and explainable
- move organization-specific logic into custom rules
- prefer several focused rules over one very broad rule
- leave broad or noisy detections disabled until you need them

Common noisy candidates:

- generic token assignment patterns
- broad business-sensitive filename rules
- conservative PII-like content matches

## Custom Rules

Recommended workflow:

1. leave `configs/rules/default/` as the shipped baseline
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

See also:

- `docs/tuning.md`
- `docs/workflows.md`
- `examples/rules/custom/example.yml`
