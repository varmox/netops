"""Vulnerability watch: CVE feeds + LAN scan -> findings -> alerts -> remediation on approval.

Sources
  - CISA KEV: actively exploited CVEs (vendor/product names, no versions).
  - NVD API 2.0: every CVE for each product CPE in the inventory, with version ranges, evaluated locally.
  - nmap -sV with the vulners script: services found on LAN hosts and the CVEs vulners.com lists for them.
  - Cloudflare's CVE blog feed: news only (Zero Wire has no machine-readable feed).

A finding is (CVE, host). New findings go to ntfy with one-click action links; nothing on the network
changes until someone approves an action (remediation.py).
"""
import asyncio
import json
import logging
import os
import re
import socket
import time
import xml.etree.ElementTree as ET

import httpx

from . import alerts, backups, inventory, settings

log = logging.getLogger("netops.security")

SEC_DIR = settings.DATA_DIR / "security"
FINDINGS = SEC_DIR / "findings.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NEWS_URL = "https://blog.cloudflare.com/tag/cve/rss"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
FEED_HOURS = int(os.environ.get("SECURITY_FEED_HOURS", "6"))
SCAN_TIME = os.environ.get("SECURITY_SCAN_TIME", "02:30")
PUBLIC_URL = os.environ.get("NETOPS_PUBLIC_URL", "https://netops.lan").rstrip("/")

STATUS = {"scan": None, "feeds": None, "running": None}   # last run times, current job


# ---------------------------------------------------------------- versions and CPE matching

def _vparts(v: str) -> list:
    return [int(p) if p.isdigit() else p for p in re.split(r"[.\-_+()]", v.lower()) if p]


def vcmp(a: str, b: str) -> int:
    pa, pb = _vparts(a), _vparts(b)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        return -1 if str(x) < str(y) else 1
    return (len(pa) > len(pb)) - (len(pa) < len(pb))


def _cpe_vp(cpe: str) -> tuple[str, str]:
    p = cpe.split(":")
    return (p[3], p[4]) if len(p) > 4 else ("", "")


_VERSIONISH = re.compile(r"^[vV]?\d+(\.\d+)*([a-z0-9.\-_()]*)$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
BOUNDS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")


def match_version(m: dict, version: str) -> bool | None:
    """One NVD cpeMatch entry against a concrete version.

    True/False only when NVD gives a usable version (or range). None when it can't decide: a wildcard
    without any range ("all versions", common for old CVEs), or bounds that are dates, not versions.
    """
    exact = m["criteria"].split(":")[5]
    if exact not in ("*", "-", ""):
        return vcmp(version, exact) == 0
    bounds = {k: m[k] for k in BOUNDS if k in m}
    if not bounds or any(_DATE.match(v) or not _VERSIONISH.match(v) for v in bounds.values()):
        return None
    if "versionStartIncluding" in m and vcmp(version, m["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in m and vcmp(version, m["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in m and vcmp(version, m["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in m and vcmp(version, m["versionEndExcluding"]) >= 0:
        return False
    return True


def nvd_affects(cve: dict, cpe: str, version: str | None) -> bool | None:
    """True: a version range includes the device's version. False: no entry for the product, or every range
    excludes the version. None: undecidable (version unknown, or NVD has no usable range)."""
    vendor, product = _cpe_vp(cpe)
    hits = [m for cfg in cve.get("configurations", []) for node in cfg.get("nodes", [])
            for m in node.get("cpeMatch", []) if m.get("vulnerable") and _cpe_vp(m["criteria"]) == (vendor, product)]
    if not hits:
        return False
    if not version:
        return None
    results = [match_version(m, version) for m in hits]
    if any(r is True for r in results):
        return True
    return None if any(r is None for r in results) else False


def cvss(cve: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in cve.get("metrics", {}).get(key, []):
            d = m.get("cvssData", {})
            if "baseScore" in d:
                return d["baseScore"], d.get("baseSeverity") or m.get("baseSeverity")
    return None, None


def severity_of(score: float | None, kev: bool) -> str:
    if kev or (score or 0) >= 9:
        return "critical"
    if (score or 0) >= 7:
        return "high"
    if (score or 0) >= 4:
        return "medium"
    return "low"


# ---------------------------------------------------------------- inventory

def software_inventory() -> list[dict]:
    """Every (device, product) to check, with the version read from the device where possible."""
    out = []
    for dev in inventory.load():
        for sw in dev.software:
            version = sw.get("version") or _detected_version(dev, sw.get("version_from"))
            out.append({"device": dev.id, "device_name": dev.name, "host": dev.host, "cpe": sw["cpe"],
                        "kev": sw.get("kev"), "version": version, "name": sw.get("name") or sw["cpe"].split(":")[4]})
    return out


def _detected_version(dev, source: str | None) -> str | None:
    latest = backups.latest(dev.id)
    if not latest or not source:
        return None
    text = backups.read(dev.id, latest["primary"])
    if source == "mikrotik":
        m = re.search(r"by RouterOS (\S+)", text)
        return m.group(1) if m else None
    if source == "zyxel":
        m = re.search(r'"SoftwareVersion":\s*"([^"]+)"', text)
        return m.group(1) if m else None
    return None


# ---------------------------------------------------------------- findings store

def load() -> dict[str, dict]:
    return json.loads(FINDINGS.read_text()) if FINDINGS.is_file() else {}


def save(findings: dict[str, dict]) -> None:
    SEC_DIR.mkdir(parents=True, exist_ok=True)
    tmp = FINDINGS.with_suffix(".tmp")
    tmp.write_text(json.dumps(findings, indent=1))
    tmp.replace(FINDINGS)


async def upsert(new: list[dict]) -> list[dict]:
    """Merge findings from one source; returns the ones never seen before."""
    findings = load()
    now = time.time()
    fresh = []
    for f in new:
        key = "%s@%s" % (f["cve"], f["host"])
        old = findings.get(key)
        if old:
            old.update({k: v for k, v in f.items() if v is not None and k not in ("status", "first_seen")})
            old["sources"] = sorted(set(old.get("sources", [])) | set(f.get("sources", [])))
            old["last_seen"] = now
        else:
            f.update({"id": key, "status": "open", "first_seen": now, "last_seen": now, "history": []})
            findings[key] = f
            fresh.append(f)
    save(findings)
    return fresh


def reconcile(source: str, found: list[dict]) -> int:
    """Findings that came only from `source` and are no longer reported by it are resolved (e.g. after an update)."""
    keys = {"%s@%s" % (f["cve"], f["host"]) for f in found}
    findings, n = load(), 0
    for key, f in findings.items():
        only_this = set(f.get("sources", [])) - {"kev"} == {source}
        if only_this and key not in keys and f["status"] in ("open", "acknowledged", "remediating"):
            f["status"] = "resolved"
            f.setdefault("history", []).append({"time": time.time(), "action": "auto-resolve", "by": source,
                                                "result": "no longer reported by %s" % source})
            n += 1
    save(findings)
    return n


async def announce(fresh: list[dict]) -> None:
    from . import remediation   # circular at import time
    for f in sorted(fresh, key=lambda x: -(x.get("score") or 0))[:20]:
        if f["severity"] not in ("critical", "high"):
            continue
        actions = [("view", "Open", "%s/security?finding=%s" % (PUBLIC_URL, f["id"]))]
        for act in remediation.proposals(f):
            actions.append(("http", act["label"], "%s/api/security/act/%s" % (PUBLIC_URL, remediation.action_token(f["id"], act["action"]))))
        title = "%s %s on %s" % (f["severity"].upper(), f["cve"], f.get("device_name") or f["host"])
        msg = "%s%s\n%s" % ("Actively exploited (CISA KEV). " if f.get("kev") else "",
                            f.get("product", ""), (f.get("summary") or "")[:300])
        await alerts.notify(title, msg, "critical" if f["severity"] == "critical" else "warning", f.get("device"),
                            actions=actions)


# ---------------------------------------------------------------- feeds

async def _get_json(client: httpx.AsyncClient, url: str, **params) -> dict:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY and url.startswith(NVD_URL) else {}
    r = await client.get(url, params=params, headers=headers, timeout=120)
    r.raise_for_status()
    return r.json()


async def sync_feeds() -> dict:
    """KEV + NVD per inventory product -> findings for devices whose version is affected."""
    SEC_DIR.mkdir(parents=True, exist_ok=True)
    found, kev_ids = [], {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        kev = await _get_json(client, KEV_URL)
        (SEC_DIR / "kev.json").write_text(json.dumps(kev))
        kev_ids = {v["cveID"]: v for v in kev["vulnerabilities"]}

        for sw in software_inventory():
            vendor, product = _cpe_vp(sw["cpe"])
            data = await _get_json(client, NVD_URL, virtualMatchString="cpe:2.3:%s:%s:%s" % (
                sw["cpe"].split(":")[2], vendor, product), resultsPerPage=2000)
            await asyncio.sleep(0 if NVD_API_KEY else 6.5)   # NVD: 5 requests / 30 s without a key
            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                affected = nvd_affects(cve, sw["cpe"], sw["version"])
                k = kev_ids.get(cve["id"])
                # Undecidable (unknown version, or NVD without a usable range): only report what is
                # actively exploited, flagged for checking.
                if affected is False or (affected is None and not k):
                    continue
                score, _ = cvss(cve)
                desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
                found.append({
                    "cve": cve["id"], "host": sw["host"], "device": sw["device"], "device_name": sw["device_name"],
                    "product": "%s %s" % (sw["name"], sw["version"] or "(version unknown)"),
                    "score": score, "kev": bool(k), "severity": severity_of(score, bool(k)),
                    "summary": (k or {}).get("vulnerabilityName") or desc[:400],
                    "required_action": (k or {}).get("requiredAction"),
                    "confidence": "confirmed" if affected else "check version",
                    "published": cve.get("published"), "sources": ["nvd"] + (["kev"] if k else []),
                    "references": [r["url"] for r in cve.get("references", [])][:6],
                })
    fresh = await upsert(found)
    resolved = reconcile("nvd", found)
    STATUS["feeds"] = time.time()
    await announce(fresh)
    return {"matched": len(found), "new": len(fresh), "resolved": resolved, "kev_entries": len(kev_ids)}


async def news() -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            r = await c.get(NEWS_URL)
        root = ET.fromstring(r.content)
        return [{"title": i.findtext("title"), "link": i.findtext("link"), "date": i.findtext("pubDate")}
                for i in root.iter("item")][:10]
    except Exception as e:   # news is a nice-to-have
        log.warning("news feed: %s", e)
        return []


# ---------------------------------------------------------------- LAN scan

def _resolve(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


async def scan_targets() -> list[str]:
    """Inventory hosts plus every active DHCP lease the MikroTik reports (via mktxp in Prometheus)."""
    hosts = {d.host for d in inventory.load()}
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(os.environ.get("PROMETHEUS_URL", "http://prometheus:9090") + "/api/v1/query",
                            params={"query": "mktxp_dhcp_lease_info"})
        hosts |= {x["metric"]["address"] for x in r.json()["data"]["result"] if x["metric"].get("address")}
    except Exception as e:
        log.warning("could not read DHCP leases: %s", e)
    def order(h: str):   # IPs numerically first, then host names
        parts = h.split(".")
        return (0, tuple(int(p) for p in parts), "") if all(p.isdigit() for p in parts) else (1, (), h)
    return sorted(hosts, key=order)


# Services that send credentials in clear text: reported as exposure findings even without a CVE.
RISKY_SERVICES = {
    "telnet": ("high", "Telnet is open: logins and everything typed travel unencrypted. Disable it; use SSH."),
    "ftp": ("medium", "FTP is open: logins travel unencrypted. Disable it, or use SFTP."),
    "tftp": ("medium", "TFTP is open: no authentication at all. Disable it."),
    "snmp": ("medium", "SNMP is open: community strings travel unencrypted. Disable it or use SNMPv3."),
    "vnc": ("high", "VNC is open on the LAN. Restrict it or put it behind SSH."),
}


def exposure_findings(services: list[dict], by_host: dict) -> list[dict]:
    out = []
    for s in services:
        risk = RISKY_SERVICES.get(s.get("service") or "")
        if not risk:
            continue
        dev = by_host.get(s["host"])
        sev, text = risk
        out.append({
            "cve": "EXPOSURE-%s-%d" % (s["service"].upper(), s["port"]), "host": s["host"],
            "device": dev.id if dev else None, "device_name": dev.name if dev else s["host"],
            "product": "%s on port %d %s" % (s["service"], s["port"], s.get("product") or ""), "score": None,
            "kev": False, "severity": sev, "summary": text, "required_action": None, "confidence": "service open",
            "sources": ["nmap"], "references": [],
        })
    return out


def parse_nmap(xml_text: str) -> tuple[list[dict], list[dict]]:
    """-> (services per host, vulners findings)"""
    root = ET.fromstring(xml_text)
    services, vulns = [], []
    for host in root.iter("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        ip = addr.get("addr")
        for port in host.iter("port"):
            if port.find("state") is None or port.find("state").get("state") != "open":
                continue
            svc = port.find("service")
            services.append({"host": ip, "port": int(port.get("portid")), "proto": port.get("protocol"),
                             "service": svc.get("name") if svc is not None else None,
                             "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else "",
                             "cpe": [c.text for c in svc.findall("cpe")] if svc is not None else []})
            for script in port.findall("script[@id='vulners']"):
                for table in script.findall("table"):
                    cpe = table.get("key")
                    for entry in table.findall("table"):
                        e = {el.get("key"): el.text for el in entry.findall("elem")}
                        if e.get("type") != "cve" or not e.get("id", "").startswith("CVE-"):
                            continue
                        score = float(e["cvss"]) if e.get("cvss") else None
                        vulns.append({"cve": e["id"], "host": ip, "score": score, "port": int(port.get("portid")),
                                      "product": "%s (port %s)" % (svc.get("product") or cpe, port.get("portid")),
                                      "cpe": cpe, "exploit": e.get("is_exploit") == "true"})
    return services, vulns


async def scan_lan() -> dict:
    targets = await scan_targets()
    STATUS["running"] = "scan"
    try:
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sT", "-Pn", "-sV", "--version-light", "--top-ports", "200", "-T4",
            "--script", "vulners", "--script-args", "mincvss=5.0", "-oX", "-", *targets,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=3600)
    finally:
        STATUS["running"] = None
    if proc.returncode != 0:
        raise RuntimeError("nmap failed: %s" % err.decode()[-300:])
    services, vulns = parse_nmap(out.decode())
    (SEC_DIR / "services.json").write_text(json.dumps({"time": time.time(), "targets": targets, "services": services}))

    kev = json.loads((SEC_DIR / "kev.json").read_text())["vulnerabilities"] if (SEC_DIR / "kev.json").is_file() else []
    kev_ids = {v["cveID"]: v for v in kev}
    by_host = {}
    managed = set()   # Linux hosts with SSH: apt/dnf + Trivy know the real package versions
    for d in inventory.load():
        for addr in {d.host, _resolve(d.host)} - {None}:
            by_host[addr] = d
            if d.type == "linux" and d.ssh:
                managed.add(addr)

    # vulners only sees the version in the service banner; distributions backport fixes without changing it,
    # so these are grouped per service and capped at medium unless a CVE is actively exploited.
    groups: dict[tuple, list[dict]] = {}
    for v in vulns:
        if v["host"] not in managed:
            groups.setdefault((v["host"], v["port"], v["product"]), []).append(v)
    found = []
    for (host, port, product), vs in groups.items():
        dev = by_host.get(host)
        items = sorted(({"id": v["cve"], "pkg": product, "installed": "", "fixed": "",
                         "severity": "cvss %s" % v["score"], "kev": v["cve"] in kev_ids} for v in vs),
                       key=lambda i: (not i["kev"], i["id"]))
        kev_hit = any(i["kev"] for i in items)
        top = max((v["score"] or 0) for v in vs)
        found.append({
            "cve": "SERVICE %s" % product, "host": host, "device": dev.id if dev else None,
            "device_name": dev.name if dev else host, "product": product, "score": top, "kev": kev_hit,
            "severity": "critical" if kev_hit else ("medium" if top >= 7 else "low"),
            "summary": "%d CVEs listed for this service version (highest CVSS %.1f). Based on the service banner: "
                       "if the vendor backports fixes, the device may already be patched." % (len(vs), top),
            "required_action": next((kev_ids[i["id"]]["requiredAction"] for i in items if i["kev"]), None),
            "confidence": "service banner", "sources": ["nmap"] + (["kev"] if kev_hit else []),
            "references": [], "items": items,
        })
    found += exposure_findings(services, by_host)
    fresh = await upsert(found)
    reconcile("nmap", found)
    await announce(fresh)
    # Linux hosts: OS updates over SSH and Trivy for running container images.
    from . import linux
    STATUS["running"] = "hosts"
    try:
        hosts = await linux.scan_all()
    finally:
        STATUS["running"] = None
    STATUS["scan"] = time.time()
    return {"targets": len(targets), "services": len(services), "findings": len(found), "new": len(fresh), "hosts": hosts}


def services() -> dict:
    p = SEC_DIR / "services.json"
    return json.loads(p.read_text()) if p.is_file() else {"time": None, "targets": [], "services": []}


# ---------------------------------------------------------------- scheduling

async def scheduler() -> None:
    from .jobs import _seconds_until
    await asyncio.sleep(30)

    from . import features

    async def feeds_loop():
        while True:
            if features.enabled("security"):
                try:
                    await sync_feeds()
                except Exception:
                    log.exception("feed sync failed")
            await asyncio.sleep(FEED_HOURS * 3600)

    async def scan_loop():
        while True:
            await asyncio.sleep(_seconds_until(SCAN_TIME))
            if features.enabled("security"):
                try:
                    await scan_lan()
                except Exception:
                    log.exception("LAN scan failed")

    await asyncio.gather(feeds_loop(), scan_loop())

