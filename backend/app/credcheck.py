"""Default-credential audit (feature 5) — a defensive posture check for your OWN LAN.

Weak or unchanged factory passwords are how Mirai-style botnets take over home devices. This audit tries a
short list of *publicly documented* factory logins against devices you own and reports which ones still
accept them, so you can change them. It does not store or reveal any password beyond those public defaults,
and it never changes anything on a device.

Guard rails (this is a credential-testing tool, so it stays narrow):
  - OFF unless CREDCHECK_ENABLED=true, AND every run needs an explicit confirm flag from the UI.
  - Targets must be private (RFC1918 / link-local) addresses on your own network; anything else is refused.
  - Hard cap on targets per run, one probe per credential, short timeouts, a small pause between hosts.
  - Stops at the first factory login that works on a host (we only need to know it's vulnerable).
  - Every run is written to the security audit log.
"""
import asyncio
import ipaddress
import json
import logging
import time

from . import alerts, inventory, security, settings

log = logging.getLogger("netops.credcheck")

STATE = security.SEC_DIR / "credcheck.json"
MAX_TARGETS = 64
PER_HOST_PAUSE = 1.0

# Publicly documented factory defaults (vendor manuals, router-default lists). Used only to tell you a
# device still accepts its out-of-the-box login.
DEFAULTS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "1234"),
    ("root", "root"), ("root", ""), ("root", "admin"), ("root", "calvin"),
    ("user", "user"), ("ubnt", "ubnt"), ("admin", "changeme"), ("support", "support"),
    ("admin", "admin1234"),
]


def _is_lan(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local


def load() -> dict:
    return json.loads(STATE.read_text()) if STATE.is_file() else {"time": None, "results": []}


async def _try_ssh(host: str, port: int) -> tuple[str, str] | None:
    import asyncssh
    for user, pw in DEFAULTS:
        try:
            async with asyncssh.connect(host, port=port, username=user, password=pw, known_hosts=None,
                                        connect_timeout=6, login_timeout=6,
                                        preferred_auth=["password", "keyboard-interactive"]):
                return user, pw
        except asyncssh.PermissionDenied:
            continue
        except (OSError, asyncssh.Error, asyncio.TimeoutError):
            return None
    return None


async def _try_telnet(host: str, port: int) -> tuple[str, str] | None:
    for user, pw in DEFAULTS:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        except (OSError, asyncio.TimeoutError):
            return None
        try:
            await asyncio.wait_for(reader.read(512), timeout=4)          # login:
            writer.write((user + "\r\n").encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=4)          # Password:
            writer.write((pw + "\r\n").encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=4)
            text = resp.decode(errors="replace").lower()
            if any(s in text for s in ("incorrect", "fail", "denied", "login:")):
                continue
            if any(p in resp.decode(errors="replace") for p in ("#", "$", ">")):
                return user, pw
        except (OSError, asyncio.TimeoutError):
            continue
        finally:
            writer.close()
    return None


async def _try_http(host: str, port: int) -> tuple[str, str] | None:
    import httpx
    scheme = "https" if port in (443, 8443) else "http"
    url = "%s://%s:%d/" % (scheme, host, port)
    async with httpx.AsyncClient(verify=False, timeout=6) as c:
        try:
            probe = await c.get(url)
        except httpx.HTTPError:
            return None
        if probe.status_code != 401:          # only HTTP Basic auth is safe to test generically
            return None
        for user, pw in DEFAULTS:
            try:
                r = await c.get(url, auth=(user, pw))
            except httpx.HTTPError:
                return None
            if r.status_code not in (401, 403):
                return user, pw
    return None


PROBES = {22: _try_ssh, 2222: _try_ssh, 23: _try_telnet, 2323: _try_telnet,
          80: _try_http, 8080: _try_http, 443: _try_http, 8443: _try_http}


async def _check_host(host: str, ports: list[int]) -> dict | None:
    for port in ports:
        probe = PROBES.get(port)
        if not probe:
            continue
        hit = await probe(host, port)
        if hit:
            dev = next((d for d in inventory.load() if d.host == host), None)
            return {"host": host, "port": port, "service": probe.__name__.replace("_try_", ""),
                    "username": hit[0], "device": dev.id if dev else None,
                    "device_name": dev.name if dev else host}
    return None


async def audit(targets: list[dict], by: str = "ui") -> dict:
    """targets: [{host, ports:[...]}]. Enforces the guard rails, then probes each host."""
    from . import features
    if not features.enabled("credcheck"):
        raise PermissionError("default-credential audit is disabled (enable it under Features)")
    clean = [t for t in targets if _is_lan(t["host"])][:MAX_TARGETS]
    if not clean:
        raise ValueError("no private LAN targets to check")
    from . import remediation
    remediation._audit({"action": "credcheck-start", "by": by, "targets": len(clean)})
    results = []
    for t in clean:
        try:
            hit = await _check_host(t["host"], [int(p) for p in t.get("ports", [22, 23, 80])])
        except Exception:
            log.exception("credcheck %s failed", t["host"])
            hit = None
        if hit:
            results.append(hit)
        await asyncio.sleep(PER_HOST_PAUSE)
    security.SEC_DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"time": time.time(), "checked": len(clean), "results": results}, indent=1))
    from . import remediation as rem
    rem._audit({"action": "credcheck-done", "by": by, "checked": len(clean), "vulnerable": len(results)})
    for r in results:
        await alerts.notify("Default login still works on %s" % r["device_name"],
                            "%s accepts a factory %s login (user '%s'). Change this password now." % (
                                r["host"], r["service"], r["username"]), "critical", r["device"])
    return {"checked": len(clean), "vulnerable": len(results), "results": results}


def targets_from_inventory() -> list[dict]:
    """LAN devices with a login service in their checks, as default targets for the audit."""
    out = []
    for d in inventory.load():
        if not _is_lan(d.host):
            continue
        ports = sorted({int(c.get("target") or 0) for c in d.checks if c["type"] == "tcp"} |
                       {443 if c["type"] == "https" else 80 for c in d.checks if c["type"] in ("http", "https")})
        ports = [p for p in ports if p in PROBES] or [22, 23, 80]
        out.append({"host": d.host, "device_name": d.name, "ports": ports})
    return out
