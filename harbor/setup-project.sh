#!/usr/bin/env bash
# Creates the private Harbor project "netops" (scan on push, block pulls of images with critical CVEs)
# and a robot account that may only push/pull there. Its credentials are appended to .env, never printed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
set -a; . "$ROOT/.env"; set +a
API="http://localhost:${HARBOR_PORT:-8880}/api/v2.0"
AUTH="admin:$HARBOR_ADMIN_PASSWORD"

if [ "$(curl -s -u "$AUTH" "$API/projects?name=netops" | python3 -c 'import json,sys;print(len([p for p in json.load(sys.stdin) or [] if p["name"]=="netops"]))')" = "0" ]; then
  curl -sf -u "$AUTH" -H 'Content-Type: application/json' -X POST "$API/projects" -d '{
    "project_name": "netops",
    "metadata": {"public": "false", "auto_scan": "true", "prevent_vul": "true", "severity": "critical"}
  }' && echo "project netops created"
fi

if grep -q '^HARBOR_ROBOT_SECRET=' "$ROOT/.env"; then
  echo "robot account already in .env"; exit 0
fi
resp=$(curl -sf -u "$AUTH" -H 'Content-Type: application/json' -X POST "$API/robots" -d '{
  "name": "netops-build", "description": "NetOps: build, push and pull images", "duration": -1, "level": "project",
  "permissions": [{"kind": "project", "namespace": "netops", "access": [
    {"resource": "repository", "action": "push"}, {"resource": "repository", "action": "pull"},
    {"resource": "artifact", "action": "read"}]}]}')
python3 - "$ROOT/.env" "$resp" <<'PY'
import json, sys
r = json.loads(sys.argv[2])
with open(sys.argv[1], "a") as f:
    # single quotes: the name contains "$", which bash and docker compose would otherwise expand
    f.write("HARBOR_ROBOT_NAME='%s'\nHARBOR_ROBOT_SECRET='%s'\n" % (r["name"], r["secret"]))
print("robot account %s added to .env" % r["name"])
PY
