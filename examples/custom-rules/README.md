# Example Custom Rules

This directory is a starter location for organization-specific rules that should not modify the shipped defaults directly.

Suggested workflow:

1. Copy a relevant default rule into this directory.
2. Change the rule ID so it is unique.
3. Narrow the rule with path filters, extensions, or organization-specific naming.
4. Validate and test it before using it in a live scan.

Example:

```bash
./bin/snablr rules validate --config configs/config.yaml
./bin/snablr rules test-dir --rules examples/custom-rules --fixtures testdata/rules/fixtures --verbose
```
