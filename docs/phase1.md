# Phase 1

## Behavioral Concepts To Preserve

The upstream Snaffler codebase suggests a few design principles worth keeping, without copying its implementation:

1. Scan in stages.
   Cheap operations should happen before expensive ones: target discovery, share enumeration, directory pruning, filename triage, then content inspection.

2. Rules should be the product.
   The scanner is mostly infrastructure around a ruleset. Sensitive filename, extension, path, and content detection should live outside the binary.

3. Exclusion rules matter as much as positive detections.
   Large false-positive directories and low-value file types should be skipped early so the engine spends time on likely signal.

4. Filename rules should gate content rules.
   Content matching is more expensive and should only happen when file size, extension, path, and filename selectors suggest the file is worth reading.

5. Structured findings beat ad hoc logs.
   Findings should carry rule id, category, severity, tags, path, and matched evidence so downstream tooling can consume them cleanly.

6. Scanning logic and detection logic should stay decoupled.
   SMB enumeration, walking, reading, matching, and output should be separate packages so they can evolve independently.

7. Windows and SMB specifics should be isolated.
   Domain discovery, DFS support, SMB readers, and access semantics are platform concerns. The rule engine should not know about any of them.

## Proposed Go Architecture

The new project is built around the rule manager first, then the scanner:

- `internal/config`
  Loads runtime config from YAML and applies defaults.

- `internal/rules`
  Defines the YAML schema, loads rule packs from disk, validates them, compiles regexes, applies enable/disable overrides, and exposes fast matching methods.

- `internal/scanner`
  Coordinates walking and file processing. It asks the rule manager three questions only:
  `ShouldExclude(candidate)?`
  `MatchFilename(candidate)?`
  `MatchContent(candidate)?`

- `internal/smb`
  Holds interfaces and future implementations for SMB share enumeration, walking, and file reading. This keeps SMB-specific code out of the scanner and rules packages.

- `internal/discovery`
  Resolves hosts and local paths into targets. In Phase 1 it supports path targets and host list loading; SMB host execution is deferred.

- `internal/output`
  Writes findings in console or JSON format through a small sink interface.

- `pkg/logx`
  Provides a minimal logger without dragging log concerns into every package.

## Rule Schema

Each YAML file is a rule pack:

```yaml
version: 1
kind: rulepack
name: default-content
description: Content rules for high-value strings.
rules:
  - id: content.inline_private_key
    enabled: true
    description: Detect PEM private key blocks in text files.
    category: credentials
    severity: critical
    type: content
    action: alert
    target: file
    field: content
    tags: [keys, private-key, pem]
    include:
      extensions: [.pem, .key, .txt]
      max_size_bytes: 1048576
    exclude:
      paths_any: [vendor, node_modules]
    match:
      strategy: regex
      patterns:
        - "-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
      case_sensitive: false
```

### Schema Fields

- `id`: globally unique rule identifier.
- `enabled`: allows file-based toggling without recompiling.
- `category`: maintenance grouping and reporting category.
- `severity`: `info|low|medium|high|critical`.
- `type`: `filename|content`.
- `action`: `alert|exclude`.
- `target`: `any|file|directory`.
- `field`:
  For filename rules: `name|path|extension`
  For content rules: `content`
- `tags`: freeform labels for filtering and grouping.
- `include`: optional preconditions.
- `exclude`: optional rule-local suppressors.
- `match.strategy`: `exact|contains|prefix|suffix|regex`.
- `match.patterns`: one or more patterns.
- `match.case_sensitive`: defaults to false in practice when omitted from sample rules.

### Selector Semantics

Selectors use:

- OR within a single list field
  Example: any matching extension in `extensions`

- AND across populated selector fields
  Example: extension must match and path must match if both are set

That means:

- `include` narrows where the rule is eligible.
- `exclude` suppresses a rule if the candidate matches all populated exclude fields.

## Loading, Validation, And Matching

### Loading

1. The config points to one or more rule directories.
2. The loader walks those directories and reads every `.yml` and `.yaml` file.
3. Every file becomes a `RulePack`.
4. Rule metadata is enriched with source file and pack name.

### Validation

Validation happens before rules are activated:

- pack kind and version are checked
- rule ids are checked for uniqueness within a pack and again across packs
- type, action, target, field, severity, and strategy are validated
- regex patterns are compiled once up front
- invalid content-exclude combinations are rejected
- obviously broken size selector ranges are rejected

This keeps runtime matching simple and predictable.

### Matching Model

The manager builds three indexes:

- filename exclude rules
- filename alert rules
- content alert rules

The scanner uses them in this order:

1. `ShouldExclude`
   Used during directory walk so noisy trees can be pruned early.

2. `MatchFilename`
   Runs on every eligible file and can emit findings without opening the file.

3. `MatchContent`
   Runs only after size checks pass and the file is read.

This keeps expensive content reads separate from rule definitions and lets the engine stay modular.

## Phase 1 Deliverable

Phase 1 includes:

- config loading
- YAML rule packs
- rule validation
- enable/disable overrides from config
- tag and minimum-severity filtering
- filename and content matching
- exclude-rule pruning during directory walks
- JSON and console outputs
- a local filesystem scanning skeleton

Phase 1 does not yet implement:

- SMB share enumeration
- DFS-aware discovery
- remote file reads over SMB
- Windows domain discovery
