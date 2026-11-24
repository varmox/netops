#!/usr/bin/env bash
# Installs Harbor (internal registry for the images NetOps builds itself) next to the NetOps stack.
#
#   harbor/install.sh          first install, or re-apply harbor.yml after changing .env
#
# - Official online installer, verified against the release's md5sum.
# - HTTP on HARBOR_PORT (default 8880), meant for the Docker host itself: Docker accepts plain HTTP for
#   localhost registries. Put it behind the NetOps nginx (HTTPS) before other machines pull from it.
# - Built-in Trivy scanner; the "netops" project scans every pushed image.
# - Harbor's stable images are amd64-only: on an ARM Mac they run under emulation (slower, fine for testing).
set -euo pipefail

VERSION="${HARBOR_VERSION:-v2.15.5}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
cd "$HERE"

set -a; . "$ROOT/.env"; set +a
: "${HARBOR_ADMIN_PASSWORD:?set HARBOR_ADMIN_PASSWORD in .env}"
PORT="${HARBOR_PORT:-8880}"

if [ ! -d harbor ]; then
  base="https://github.com/goharbor/harbor/releases/download/$VERSION"
  tgz="harbor-online-installer-$VERSION.tgz"
  curl -fsSL -o "$tgz" "$base/$tgz"
  curl -fsSL -o md5sum "$base/md5sum"
  want="$(grep " $tgz\$" md5sum | awk '{print $1}')"
  have="$( (md5sum "$tgz" 2>/dev/null || md5 -r "$tgz") | awk '{print $1}')"
  [ -n "$want" ] && [ "$want" = "$have" ] || { echo "md5 mismatch for $tgz ($have != $want)" >&2; exit 1; }
  tar xzf "$tgz" && rm -f "$tgz"
fi

DB_PASSWORD_FILE="$HERE/.db_password"
[ -s "$DB_PASSWORD_FILE" ] || (umask 077; openssl rand -hex 16 > "$DB_PASSWORD_FILE")

# harbor.yml from the template: hostname, HTTP port, no HTTPS block, passwords, data dir.
python3 - "$HERE" "$PORT" "$DB_PASSWORD_FILE" <<'PY'
import os, re, sys
here, port, dbfile = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(os.path.join(here, "harbor/harbor.yml.tmpl")).read()
t = re.sub(r"(?m)^hostname: .*$", "hostname: %s" % os.environ.get("HARBOR_HOSTNAME", "localhost"), t)
t = re.sub(r"(?m)^(http:\n  # .*\n(?:  #.*\n)*)?  port: 80$", lambda m: (m.group(1) or "") + "  port: %s" % port, t, count=1)
# comment out the https: block (certificate paths we don't use): from "https:" to the next top-level line
out, inside = [], False
for line in t.splitlines():
    if line == "https:":
        inside = True
    elif inside and line and not line.startswith((" ", "#")):
        inside = False
    out.append("# " + line if inside and line.strip() and not line.lstrip().startswith("#") else line)
t = "\n".join(out) + "\n"
t = re.sub(r"(?m)^harbor_admin_password: .*$", "harbor_admin_password: %s" % os.environ["HARBOR_ADMIN_PASSWORD"], t)
t = re.sub(r"(?m)^(database:\n(?:  #.*\n)*  password: ).*$", lambda m: m.group(1) + open(dbfile).read().strip(), t, count=1)
t = re.sub(r"(?m)^data_volume: .*$", "data_volume: %s" % os.path.join(here, "data"), t)
open(os.path.join(here, "harbor/harbor.yml"), "w").write(t)
os.chmod(os.path.join(here, "harbor/harbor.yml"), 0o600)
PY

if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
  export DOCKER_DEFAULT_PLATFORM=linux/amd64
fi
mkdir -p data
cd harbor && ./install.sh --with-trivy
