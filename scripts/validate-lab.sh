#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${SNABLR_LAB_TARGET:-10.1.10.40}"
USERNAME="${SNABLR_LAB_USER:?set SNABLR_LAB_USER for the disposable lab}"
PASSWORD="${SNABLR_LAB_PASS:?set SNABLR_LAB_PASS for the disposable lab}"
OUT_DIR="${SNABLR_LAB_OUT_DIR:-scan-results/validation}"

mkdir -p "$OUT_DIR"

./bin/snablr scan \
  --targets "$TARGET" \
  --no-ldap \
  --no-tui \
  --smb-auth password \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  --share SnablrShare01 \
  --share SnablrShare02 \
  --share SnablrShare03 \
  --share SnablrShare04 \
  --share SnablrShare05 \
  --output-format json \
  --json-out "$OUT_DIR/scan-all.json" \
  --md-out "$OUT_DIR/scan-all.md" \
  --csv-out "$OUT_DIR/scan-all.csv" \
  --scanned-targets-out "$OUT_DIR/scanned_targets.txt"

for share in \
  SnablrShare01 \
  SnablrShare02 \
  SnablrShare03 \
  SnablrShare04 \
  SnablrShare05; do
  ./bin/snablr-seed verify \
    --manifest "seed-manifests/${share}.json" \
    --results "$OUT_DIR/scan-all.json" \
    > "$OUT_DIR/verify-${share}.txt"
done

echo "Validation outputs written to $OUT_DIR"
