"""DNS filtering (feature 1) through AdGuard Home's control API, if the optional `adguard` container runs.

AdGuard Home is the network's resolver: it blocks ads/trackers/malware domains from public block lists and
keeps a per-client query log. NetOps reads its stats and query log and ties each client back to a device in
the inventory, so you can see which device asked for what — the raw material for botnet detection (phase 4),
and a strong signal on its own ("the fridge is querying a domain on a malware list").

Credentials: ADGUARD_USER / ADGUARD_PASSWORD, or the vault secret `adguard-password`.
"""
import logging

import httpx

from . import inventory, settings, vault

log = logging.getLogger("netops.dns")


def _auth() -> tuple[str, str] | None:
    user = settings.ADGUARD_USER
    try:
        pw = vault.get("adguard-password") if vault.has("adguard-password") else settings.ADGUARD_PASSWORD
    except Exception:
        pw = settings.ADGUARD_PASSWORD
    return (user, pw) if user and pw else None


async def _get(path: str, **params):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(settings.ADGUARD_URL + path, params=params, auth=_auth())
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict):
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(settings.ADGUARD_URL + path, json=body, auth=_auth())
        r.raise_for_status()
        return r.text


def _device_by_ip() -> dict:
    return {d.host: d for d in inventory.load()}


async def available() -> bool:
    try:
        await _get("/control/status")
        return True
    except Exception:
        return False


async def overview() -> dict:
    status = await _get("/control/status")
    stats = await _get("/control/stats")
    filt = await _get("/control/filtering/status")
    lists = [{"name": f.get("name"), "enabled": f.get("enabled"), "rules": f.get("rules_count"), "url": f.get("url")}
             for f in filt.get("filters", []) or []]
    return {
        "running": status.get("running", True),
        "protection_enabled": status.get("protection_enabled"),
        "dns_addresses": status.get("dns_addresses", []),
        "queries": stats.get("num_dns_queries"),
        "blocked": stats.get("num_blocked_filtering"),
        "blocked_pct": round(100 * (stats.get("num_blocked_filtering") or 0) / (stats.get("num_dns_queries") or 1), 1),
        "top_blocked": stats.get("top_blocked_domains", [])[:10],
        "top_queried": stats.get("top_queried_domains", [])[:10],
        "lists": lists,
        "user_rules": len(filt.get("user_rules", []) or []),
    }


async def top_clients() -> list[dict]:
    """Per-client query/block counts, mapped to devices."""
    stats = await _get("/control/stats")
    by_ip = _device_by_ip()
    out = []
    for entry in stats.get("top_clients", [])[:30]:
        for ip, n in entry.items():
            dev = by_ip.get(ip)
            out.append({"client": ip, "device": dev.id if dev else None,
                        "device_name": dev.name if dev else ip, "queries": n})
    return out


async def querylog(limit: int = 100, search: str = "") -> list[dict]:
    params = {"limit": limit}
    if search:
        params["search"] = search
    data = await _get("/control/querylog", **params)
    by_ip = _device_by_ip()
    out = []
    for q in data.get("data", []) or []:
        client = q.get("client")
        dev = by_ip.get(client)
        out.append({
            "time": q.get("time"), "client": client,
            "device_name": dev.name if dev else client,
            "domain": (q.get("question") or {}).get("name"),
            "type": (q.get("question") or {}).get("type"),
            "blocked": q.get("reason", "").startswith("Filtered"),
            "reason": q.get("reason"), "elapsed_ms": round(float(q.get("elapsedMs", 0) or 0), 1),
        })
    return out


async def set_protection(enabled: bool) -> str:
    await _post("/control/protection", {"enabled": enabled})
    return "protection %s" % ("enabled" if enabled else "disabled")


async def block_domain(domain: str) -> str:
    """Append a user rule blocking a domain (used by remediation to cut a device off from a C2 host)."""
    filt = await _get("/control/filtering/status")
    rules = list(filt.get("user_rules", []) or [])
    rule = "||%s^" % domain.strip().lstrip("|").rstrip("^")
    if rule not in rules:
        rules.append(rule)
        await _post("/control/filtering/set_rules", {"rules": rules})
    return "blocking %s" % domain
