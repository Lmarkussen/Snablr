#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TARGET="${SNABLR_LAB_TARGET:-10.1.10.40}"
USERNAME="${SNABLR_LAB_USER:?set SNABLR_LAB_USER for the disposable lab}"
PASSWORD="${SNABLR_LAB_PASS:?set SNABLR_LAB_PASS for the disposable lab}"
COUNT_PER_CATEGORY="${SNABLR_LAB_COUNT_PER_CATEGORY:-30}"
MAX_FILES="${SNABLR_LAB_MAX_FILES:-1050}"
DEPTH="${SNABLR_LAB_DEPTH:-1}"
RANDOM_SEED="${SNABLR_LAB_RANDOM_SEED:-1337}"

SHARES=(
  SnablrShare01
  SnablrShare02
  SnablrShare03
  SnablrShare04
  SnablrShare05
)

mkdir -p seed-manifests

for idx in "${!SHARES[@]}"; do
  share="${SHARES[$idx]}"
  share_random_seed=$((RANDOM_SEED + idx))
  ./bin/snablr-seed \
    --targets "$TARGET" \
    --username "$USERNAME" \
    --password "$PASSWORD" \
    --share "$share" \
    --count-per-category "$COUNT_PER_CATEGORY" \
    --max-files "$MAX_FILES" \
    --depth "$DEPTH" \
    --random-seed "$share_random_seed" \
    --seed-prefix SnablrLab \
    --clean-prefix \
    --manifest-out "seed-manifests/${share}.json"
done

python3 - <<'PY'
import json, glob
for path in sorted(glob.glob("seed-manifests/SnablrShare*.json")):
    data = json.load(open(path))
    positives = sum(1 for entry in data["entries"] if entry.get("intended_as") != "filler/noise")
    noise = sum(1 for entry in data["entries"] if entry.get("intended_as") == "filler/noise")
    print(path, "entries=", len(data["entries"]), "positives=", positives, "noise=", noise)
PY
