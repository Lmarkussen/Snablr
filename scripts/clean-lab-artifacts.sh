#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-.}"

LOCAL_PATHS=(
  "$ROOT/snablr"
  "$ROOT/snablr-seed"
  "$ROOT/test.html"
  "$ROOT/.cache/go-build"
  "$ROOT/notes/20260317-1338-snablr-seed.txt"
  "$ROOT/notes/20260317-1341-snablr-seed-dryrun.txt"
  "$ROOT/notes/20260317-1341-snablr-seed.txt"
  "$ROOT/notes/20260317-1343-admin-probe-administrator.txt"
  "$ROOT/notes/20260317-1343-admin-probe-dot-admin.txt"
  "$ROOT/notes/20260317-1343-admin-probe-host-admin.txt"
  "$ROOT/notes/20260317-1343-seed-probe-archive.txt"
  "$ROOT/notes/20260317-1343-seed-probe-homes-userdir.txt"
  "$ROOT/notes/20260317-1343-seed-probe-homes.txt"
  "$ROOT/notes/20260317-1343-seed-probe-public.txt"
  "$ROOT/notes/20260317-1343-seed-probe-scripts.txt"
  "$ROOT/notes/20260317-1343-snablr-seed.txt"
  "$ROOT/notes/20260317-1347-admin-probe-evilhaxxor-netbios.txt"
  "$ROOT/notes/20260317-1347-admin-probe-fqdn-domain.txt"
  "$ROOT/notes/20260317-1347-admin-probe-upn.txt"
  "$ROOT/notes/20260317-1348-snablr-seed-manifest.json"
  "$ROOT/notes/20260317-1348-snablr-seed.txt"
  "$ROOT/recon/20260317-1338-smbclient-share-list.txt"
  "$ROOT/recon/20260317-1341-smbclient-share-list.txt"
  "$ROOT/scans/20260317-1343-snablr-scan.txt"
  "$ROOT/scans/20260317-1348-snablr-scan.txt"
)

EMPTY_DIRS=(
  "$ROOT/notes"
  "$ROOT/recon"
  "$ROOT/scans"
  "$ROOT/web"
  "$ROOT/creds"
  "$ROOT/exploit"
  "$ROOT/privesc"
  "$ROOT/loot"
  "$ROOT/screenshots"
)

echo "Local paths that will be removed:"
for path in "${LOCAL_PATHS[@]}"; do
  if [ -e "$path" ]; then
    echo "  $path"
  fi
done

if [ "${SNABLR_CLEAN_ASSUME_YES:-0}" != "1" ]; then
  echo
  read -r -p "Proceed with local cleanup? [y/N] " reply
  case "$reply" in
    y|Y|yes|YES) ;;
    *) echo "Aborted."; exit 1 ;;
  esac
fi

for path in "${LOCAL_PATHS[@]}"; do
  if [ -e "$path" ]; then
    rm -rf -- "$path"
  fi
done

for dir in "${EMPTY_DIRS[@]}"; do
  if [ -d "$dir" ] && [ -z "$(find "$dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    rmdir -- "$dir"
  fi
done

echo "Local cleanup completed."
