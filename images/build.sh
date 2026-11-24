#!/usr/bin/env bash
# Builds images/<name>, pushes it to the internal Harbor (project "netops"), prints the reference.
#
#   images/build.sh mktxp
#
# Tags: <version> (what docker-compose.yml uses) and <version>-<date> (kept for rollback).
# Builds for this machine's architecture; run it on the Docker host that uses the image.
set -euo pipefail
name="${1:?usage: images/build.sh <name>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -a; . "$ROOT/.env"; set +a
: "${REGISTRY:?set REGISTRY in .env}" "${HARBOR_ROBOT_NAME:?run harbor/setup-project.sh first}" "${HARBOR_ROBOT_SECRET:?}"

dir="$ROOT/images/$name"
version="$(tr -d ' \n' < "$dir/VERSION")"
ref="$REGISTRY/netops/$name"
dated="$ref:$version-$(date +%Y%m%d)"

# One plain image manifest (no provenance/SBOM attestations): Harbor scans and tracks it as one artifact.
docker build --pull --provenance=false --sbom=false \
  --build-arg "$(echo "$name" | tr a-z A-Z)_VERSION=$version" -t "$ref:$version" -t "$dated" "$dir"
printf '%s' "$HARBOR_ROBOT_SECRET" | docker login "$REGISTRY" -u "$HARBOR_ROBOT_NAME" --password-stdin >/dev/null
docker push -q "$ref:$version"

# Harbor scans on push and blocks pulls (even the next push's HEAD) until the scan is done; wait for it.
api="http://$REGISTRY/api/v2.0/projects/netops/repositories/$name/artifacts/$version?with_scan_overview=true"
for _ in $(seq 1 120); do
  status=$(curl -s -u "$HARBOR_ROBOT_NAME:$HARBOR_ROBOT_SECRET" "$api" | python3 -c '
import json, sys
s = next(iter((json.load(sys.stdin).get("scan_overview") or {}).values()), {})
summary = (s.get("summary") or {}).get("summary") or {}
print(s.get("scan_status", "Pending"), " ".join("%s=%s" % kv for kv in sorted(summary.items())))')
  case "$status" in Success*|Error*) break ;; esac
  sleep 5
done
echo "Harbor scan: $status"
case "$status" in
  *Critical=*) echo "critical vulnerabilities: Harbor will refuse to serve this image" >&2; exit 1 ;;
  Success*) ;;
  *) echo "scan did not finish ($status)" >&2; exit 1 ;;
esac
docker push -q "$dated"
echo "$ref:$version"
