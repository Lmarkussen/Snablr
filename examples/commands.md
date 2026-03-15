# Example Commands

## Validate Rules

```bash
./bin/snablr rules validate --config configs/config.yaml
```

## Test a Rule File

```bash
./bin/snablr rules test \
  --rule configs/rules/default/content.yml \
  --input testdata/rules/fixtures/passwords/sample.conf \
  --verbose
```

## Scan a Single Host

```bash
./bin/snablr scan \
  --targets 172.16.0.90 \
  --user 'DOMAIN\user' \
  --pass 'Password123!' \
  --output-format console
```

## Run a Resumable Scan With Multiple Exports

```bash
./bin/snablr scan \
  --config examples/config.example.yaml \
  --output-format all \
  --json-out results.json \
  --html-out report.html \
  --csv-out findings.csv \
  --md-out summary.md
```

## Limit Scope to Specific Shares and Paths

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --share Finance \
  --exclude-share Backups \
  --path Policies/ \
  --max-depth 4
```
