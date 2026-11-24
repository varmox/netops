"""Firmware / OS end-of-life (feature 4). endoflife.date tells us when a product stopped getting security
updates; EOL devices are the classic botnet recruits. We look up only the product *names* in the inventory
(e.g. "ubuntu", "sonos", "debian") — no device address, MAC or version leaves the box — cache the result,
and map it against the version each device reports.

devices.yml:
  facts:
    eol_product: ubuntu        # an endoflife.date product id
    eol_cycle: "24.04"         # the release cycle/major version the device runs
"""
import asyncio
import json
import logging
import time

import httpx

from . import alerts, inventory, settings

log = logging.getLogger("netops.lifecycle")

DIR = settings.DATA_DIR / "lifecycle"
CACHE = DIR / "cache.json"
STATE = DIR / "state.json"
CACHE_TTL = 7 * 86400


def _products() -> dict[str, list[tuple[str, object]]]:
    """endoflife.date product id -> [(cycle, device)] for every device that declares one."""
    out: dict[str, list] = {}
    for dev in inventory.load():
        prod = dev.facts.get("eol_product")
        cycle = dev.facts.get("eol_cycle")
        if prod and cycle:
            out.setdefault(str(prod), []).append((str(cycle), dev))
    return out


def _cache() -> dict:
    if CACHE.is_file():
        c = json.loads(CACHE.read_text())
        if time.time() - c.get("time", 0) < CACHE_TTL:
            return c.get("data", {})
    return {}


async def _fetch(products: list[str]) -> dict:
    data = _cache()
    missing = [p for p in products if p not in data]
    if missing:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as c:
            for prod in missing:
                try:
                    r = await c.get("%s/%s.json" % (settings.EOL_URL, prod))
                    r.raise_for_status()
                    data[prod] = r.json()
                except httpx.HTTPError as e:
                    log.warning("endoflife.date %s: %s", prod, e)
                    data[prod] = []
        DIR.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps({"time": time.time(), "data": data}))
    return data


def _eol_for(cycles: list[dict], cycle: str):
    """The matching cycle's `eol` field: an ISO date, or True/False for 'already EOL' / 'still supported'."""
    for c in cycles:
        if str(c.get("cycle")) == cycle:
            return c.get("eol"), c.get("latest")
    return None, None


def _assess(eol) -> tuple[str, int | None]:
    """(status, days_left). status: eol | warn | ok | unknown."""
    if eol is True:
        return "eol", None
    if eol is False or eol is None:
        return ("ok", None) if eol is False else ("unknown", None)
    try:
        ts = time.mktime(time.strptime(eol, "%Y-%m-%d"))
    except (ValueError, TypeError):
        return "unknown", None
    days = int((ts - time.time()) / 86400)
    if days < 0:
        return "eol", days
    return ("warn", days) if days <= settings.EOL_WARN_DAYS else ("ok", days)


def load() -> dict:
    return json.loads(STATE.read_text()) if STATE.is_file() else {"time": None, "devices": []}


async def scan() -> dict:
    products = _products()
    data = await _fetch(list(products))
    prev = {d["device"]: d for d in load()["devices"]}
    rows, newly = [], []
    for prod, items in products.items():
        cycles = data.get(prod, [])
        for cycle, dev in items:
            eol, latest = _eol_for(cycles, cycle)
            status, days = _assess(eol)
            row = {"device": dev.id, "device_name": dev.name, "product": prod, "cycle": cycle,
                   "status": status, "days_left": days, "eol": eol, "latest": latest}
            rows.append(row)
            old = prev.get(dev.id)
            if status in ("eol", "warn") and (not old or old.get("status") not in ("eol", "warn")):
                newly.append(row)
    DIR.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({"time": time.time(), "devices": rows}, indent=1))
    for r in newly:
        if r["status"] == "eol":
            await alerts.notify("%s is end-of-life" % r["device_name"],
                                "%s %s no longer gets security updates. Treat it as untrusted and consider replacing or isolating it."
                                % (r["product"], r["cycle"]), "warning", r["device"])
        else:
            await alerts.notify("%s nears end-of-life" % r["device_name"],
                                "%s %s stops getting security updates in %d days." % (r["product"], r["cycle"], r["days_left"]),
                                "info", r["device"])
    return {"devices": len(rows), "eol": sum(1 for r in rows if r["status"] == "eol"), "new": len(newly)}


async def scheduler() -> None:
    from . import features
    await asyncio.sleep(60)
    while True:
        if features.enabled("lifecycle"):
            try:
                await scan()
            except Exception:
                log.exception("lifecycle scan failed")
        await asyncio.sleep(CACHE_TTL)
