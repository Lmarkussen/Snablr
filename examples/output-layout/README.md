# Example Output Layout

Typical generated artifacts:

```text
results.json     machine-readable structured findings
report.html      standalone interactive HTML triage report
findings.csv     spreadsheet-friendly flat export
summary.md       lightweight Markdown summary for tickets or notes
state/
  checkpoint.json resumable scan state
```

Suggested layout for a longer engagement:

```text
output/
  run-2026-03-15/
    results.json
    report.html
    findings.csv
    summary.md
    state/
      checkpoint.json
```

Example invocation:

```bash
./bin/snablr scan \
  --config configs/config.yaml \
  --output-format all \
  --json-out output/run-2026-03-15/results.json \
  --html-out output/run-2026-03-15/report.html \
  --csv-out output/run-2026-03-15/findings.csv \
  --md-out output/run-2026-03-15/summary.md \
  --checkpoint-file output/run-2026-03-15/state/checkpoint.json
```
