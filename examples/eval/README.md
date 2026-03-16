# Evaluation Examples

This directory contains a small safe dataset, a benchmark config, and labels for the `snablr benchmark` and `snablr eval` workflows.

Files:
- `benchmark.yaml`: example benchmark configuration
- `labels.yaml`: labeled expectations for the sample dataset
- `dataset/`: small synthetic corpus for local testing

Quick commands:

```bash
snablr benchmark --config examples/eval/benchmark.yaml --out benchmark.json
snablr eval --dataset examples/eval/dataset --labels examples/eval/labels.yaml --out eval.json
```
