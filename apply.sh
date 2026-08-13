#!/usr/bin/env bash
set -euo pipefail

ORGS=("6j0-org" "devopscoop")

for org in "${ORGS[@]}"; do
  echo "=== $org ==="
  gh repo list "$org" --limit 1000 --json name --jq '.[].name' | while read -r repo; do
    echo "--- $org/$repo ---"
    gh api -X PUT "/repos/$org/$repo/branches/main/protection" \
      --input branch-protection.json
    echo ""
  done
done
