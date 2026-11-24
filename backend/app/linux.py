"""Linux hosts over SSH: pending OS updates (apt/dnf) and Trivy scans of running container images.

devices.yml:
  - id: server1
    type: linux
    host: 192.168.8.20
    ssh: { user: netops, key: /secrets/linux_id_ed25519, port: 22 }
    docker: true          # also scan running container images with Trivy

The SSH user needs passwordless sudo for the package manager only (see README), and membership in the
docker group for Trivy and container updates. One finding per host (updates) and per image (Trivy), with
the individual packages/CVEs in `items`; actively exploited CVEs (CISA KEV) make it critical.
"""
import json
import logging
import re
import shlex

import asyncssh

from . import inventory, security, vault

log = logging.getLogger("netops.linux")

TRIVY_IMAGE = "aquasec/trivy:0.76.2"
TRIVY_CACHE = "netops-trivy-cache"     # docker volume on the scanned host, so the DB isn't fetched every time


async def run(dev, cmd: str, timeout: int = 900, check: bool = False) -> asyncssh.SSHCompletedProcess:
    cfg = dev.ssh or {}
    async with asyncssh.connect(dev.host, port=int(cfg.get("port", 22)), username=cfg["user"],
                                client_keys=[asyncssh.import_private_key(vault.secret_or_file(cfg, "key_vault", "key"))],
                                known_hosts=None,
                                connect_timeout=15) as conn:
        return await conn.run(cmd, check=check, timeout=timeout)


def linux_hosts() -> list:
    return [d for d in inventory.load() if d.type == "linux" and d.ssh]


# ---------------------------------------------------------------- OS updates

DETECT = ". /etc/os-release 2>/dev/null; echo \"$ID|$VERSION_ID|$PRETTY_NAME\"; " \
         "command -v apt-get >/dev/null && echo apt || (command -v dnf >/dev/null && echo dnf || echo none); " \
         "[ -f /var/run/reboot-required ] && echo reboot || echo noreboot"


async def os_updates(dev) -> dict:
    r = await run(dev, DETECT, timeout=30)
    lines = r.stdout.strip().splitlines()
    distro = lines[0].split("|")
    pm, reboot = lines[1], lines[2] == "reboot"
    items = []
    if pm == "apt":
        out = (await run(dev, "sudo -n apt-get -qq update >/dev/null 2>&1; apt list --upgradable 2>/dev/null", timeout=300)).stdout
        items = parse_apt(out)
    elif pm == "dnf":
        sec = (await run(dev, "dnf -q updateinfo list --security 2>/dev/null | awk '{print $3}'", timeout=300)).stdout.split()
        out = (await run(dev, "dnf -q check-update 2>/dev/null; true", timeout=300)).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3 and "." in parts[0]:
                name = parts[0].rsplit(".", 1)[0]
                items.append({"id": name, "pkg": name, "installed": "", "fixed": parts[1],
                              "severity": "security" if any(s.startswith(name + "-") for s in sec) else "update"})
    return {"distro": distro[2] if len(distro) > 2 else distro[0], "pm": pm, "reboot": reboot, "items": items}


def parse_apt(out: str) -> list[dict]:
    """`apt list --upgradable` -> items. Lines look like
    "openssl/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.14-1~deb12u2]"."""
    items = []
    for line in out.splitlines():
        if "/" not in line or "upgradable from" not in line:
            continue
        name, rest = line.split("/", 1)
        suite, new = rest.split()[0], rest.split()[1]
        old = line.rsplit("upgradable from: ", 1)[-1].rstrip("]")
        items.append({"id": name, "pkg": name, "installed": old, "fixed": new,
                      "severity": "security" if "security" in suite else "update"})
    return items


def updates_finding(dev, info: dict) -> dict | None:
    items = info["items"]
    n_sec = sum(1 for i in items if i["severity"] == "security")
    if not items and not info["reboot"]:
        return None
    sev = "high" if n_sec else "low"
    summary = "%d pending updates (%d security) on %s%s." % (
        len(items), n_sec, info["distro"], "; a reboot is pending" if info["reboot"] else "")
    return {
        "cve": "UPDATES", "host": dev.host, "device": dev.id, "device_name": dev.name,
        "product": "%s (%s)" % (info["distro"], info["pm"]), "score": None, "kev": False, "severity": sev,
        "summary": summary, "required_action": None, "confidence": "package manager", "sources": ["updates"],
        "references": [], "items": items[:300],
        "remedy": [{"action": "apply-updates", "label": "Install updates",
                    "description": "Runs %s on %s. Services may restart; no reboot." % (
                        "apt-get upgrade" if info["pm"] == "apt" else "dnf upgrade", dev.name)}] if items else [],
    }


async def apply_updates(dev) -> str:
    r = await run(dev, DETECT, timeout=30)
    pm = r.stdout.strip().splitlines()[1]
    if pm == "apt":
        cmd = ("sudo -n apt-get -qq update && sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -y "
               "-o Dpkg::Options::=--force-confold upgrade")
    elif pm == "dnf":
        cmd = "sudo -n dnf -y upgrade"
    else:
        raise RuntimeError("no supported package manager on %s" % dev.name)
    r = await run(dev, cmd, timeout=1800)
    if r.exit_status != 0:
        raise RuntimeError("update failed (%s): %s" % (r.exit_status, (r.stderr or r.stdout)[-300:]))
    tail = [l for l in r.stdout.splitlines() if "upgraded" in l]
    return "updated %s: %s" % (dev.name, tail[-1] if tail else "done")


# ---------------------------------------------------------------- containers (Trivy)

async def containers(dev) -> list[dict]:
    out = (await run(dev, "docker ps --format '{{json .}}'", timeout=60, check=True)).stdout
    rows = [json.loads(l) for l in out.splitlines() if l.strip()]
    for c in rows:
        labels = dict(kv.split("=", 1) for kv in c.get("Labels", "").split(",") if "=" in kv)
        c["compose_project"] = labels.get("com.docker.compose.project")
        c["compose_service"] = labels.get("com.docker.compose.service")
        c["compose_dir"] = labels.get("com.docker.compose.project.working_dir")
    return rows


async def trivy_image(dev, image: str) -> dict:
    if re.fullmatch(r"(sha256:)?[0-9a-f]{12,64}", image):
        # Containers of rebuilt/untagged images only report an image ID; Trivy needs the full one.
        r = await run(dev, "docker image inspect --format '{{.Id}}' %s" % shlex.quote(image), timeout=60)
        if r.exit_status != 0:
            # The container runs an image that was since removed (e.g. rebuilt); nothing left to scan.
            raise LookupError("image %s no longer exists (recreate the container)" % image)
        image = r.stdout.strip()
    cmd = ("docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v %s:/root/.cache/ %s image --quiet "
           "--format json --scanners vuln --severity CRITICAL,HIGH,MEDIUM --ignore-unfixed --timeout 15m %s") % (
        TRIVY_CACHE, TRIVY_IMAGE, shlex.quote(image))
    r = await run(dev, cmd, timeout=1800)
    if r.exit_status != 0:
        raise RuntimeError("trivy failed for %s: %s" % (image, (r.stderr or "")[-300:]))
    return json.loads(r.stdout)


def image_finding(dev, image: str, report: dict, users: list[dict], kev_ids: set[str]) -> dict | None:
    items = []
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            items.append({"id": v["VulnerabilityID"], "pkg": v.get("PkgName"), "installed": v.get("InstalledVersion"),
                          "fixed": v.get("FixedVersion"), "severity": v.get("Severity", "").lower(),
                          "title": (v.get("Title") or "")[:160], "kev": v["VulnerabilityID"] in kev_ids})
    if not items:
        return None
    counts = {s: sum(1 for i in items if i["severity"] == s) for s in ("critical", "high", "medium")}
    kev = any(i["kev"] for i in items)
    sev = "critical" if kev or counts["critical"] else "high" if counts["high"] else "medium"
    composed = [c for c in users if c.get("compose_service") and c.get("compose_dir")]
    names = ", ".join(c["Names"] for c in users)
    remedy = []
    if composed:
        remedy.append({"action": "update-container", "label": "Update container",
                       "description": "docker compose pull + up -d for %s on %s (short restart)." % (
                           ", ".join(c["compose_service"] for c in composed), dev.name),
                       "params": [{"dir": c["compose_dir"], "service": c["compose_service"]} for c in composed]})
    items.sort(key=lambda i: (not i["kev"], ["critical", "high", "medium"].index(i["severity"]) if i["severity"] in ("critical", "high", "medium") else 9))
    return {
        "cve": "IMAGE %s" % image, "host": dev.host, "device": dev.id, "device_name": dev.name,
        "product": "%s (container %s)" % (image, names), "score": None, "kev": kev, "severity": sev,
        "summary": "%d critical, %d high, %d medium vulnerabilities with a fix available%s." % (
            counts["critical"], counts["high"], counts["medium"], "; includes actively exploited CVEs" if kev else ""),
        "required_action": None, "confidence": "trivy", "sources": ["trivy"] + (["kev"] if kev else []),
        "references": [], "items": items[:300], "remedy": remedy,
    }


async def update_container(dev, params: list[dict]) -> str:
    done = []
    for p in params:
        d, s = shlex.quote(p["dir"]), shlex.quote(p["service"])
        r = await run(dev, "cd %s && docker compose pull %s && docker compose up -d %s" % (d, s, s), timeout=1800)
        if r.exit_status != 0:
            raise RuntimeError("update of %s failed: %s" % (p["service"], (r.stderr or r.stdout)[-300:]))
        done.append(p["service"])
    return "pulled and restarted %s on %s" % (", ".join(done), dev.name)


# ---------------------------------------------------------------- scan all

async def scan_all() -> dict:
    kev_path = security.SEC_DIR / "kev.json"
    kev_ids = {v["cveID"] for v in json.loads(kev_path.read_text())["vulnerabilities"]} if kev_path.is_file() else set()
    upd, img, errors = [], [], []
    for dev in linux_hosts():
        try:
            f = updates_finding(dev, await os_updates(dev))
            if f:
                upd.append(f)
        except Exception as e:
            errors.append("%s updates: %s" % (dev.id, e))
        if not dev.docker:
            continue
        try:
            by_image: dict[str, list[dict]] = {}
            for c in await containers(dev):
                by_image.setdefault(c["Image"], []).append(c)
            for image, users in by_image.items():
                try:
                    report = await trivy_image(dev, image)
                except LookupError as e:
                    log.info("%s: skipped %s", dev.id, e)
                    continue
                f = image_finding(dev, image, report, users, kev_ids)
                if f:
                    img.append(f)
        except Exception as e:
            errors.append("%s trivy: %s" % (dev.id, e))
    fresh = await security.upsert(upd + img)
    if not errors:   # only resolve when every host answered, so an outage doesn't "fix" findings
        security.reconcile("updates", upd)
        security.reconcile("trivy", img)
    await security.announce(fresh)
    for e in errors:
        log.warning(e)
    return {"hosts": len(linux_hosts()), "update_findings": len(upd), "image_findings": len(img),
            "new": len(fresh), "errors": errors}
