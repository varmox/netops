"""Reliability numbers for the latency/health feature: availability, MTTR, MTBF and latency percentiles.

Downtime is recorded as incidents (a device leaving "up" until it returns) in data/reliability/incidents.jsonl,
written from the health watcher's state transitions. Latency percentiles (p5/p50/p95) come from Prometheus,
which already stores netops_check_latency_ms, via quantile_over_time over a window.
"""
import json
import logging
import os
import time

import httpx

from . import settings

log = logging.getLogger("netops.reliability")

DIR = settings.DATA_DIR / "reliability"
LOG = DIR / "incidents.jsonl"
PROM = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")


def _append(entry: dict) -> None:
    DIR.mkdir(parents=True, exist_ok=True)
    with LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def _incidents() -> list[dict]:
    if not LOG.is_file():
        return []
    return [json.loads(line) for line in LOG.read_text().splitlines() if line.strip()]


def incident_open(device_id: str) -> None:
    """A device just left 'up'. Only opens one if none is currently open for it."""
    if _open_for(device_id) is None:
        _append({"device": device_id, "start": time.time(), "end": None})


def incident_close(device_id: str) -> None:
    """A device is 'up' again: close its open incident (rewrites the log with the end time filled in)."""
    rows = _incidents()
    changed = False
    for r in reversed(rows):
        if r["device"] == device_id and r["end"] is None:
            r["end"] = time.time()
            changed = True
            break
    if changed:
        DIR.mkdir(parents=True, exist_ok=True)
        tmp = LOG.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(r) + "\n" for r in rows))
        tmp.replace(LOG)


def _open_for(device_id: str) -> dict | None:
    return next((r for r in reversed(_incidents()) if r["device"] == device_id and r["end"] is None), None)


def _stats(device_id: str, window_s: float) -> dict:
    now = time.time()
    since = now - window_s
    durations, downtime, count = [], 0.0, 0
    for r in _incidents():
        if r["device"] != device_id:
            continue
        end = r["end"] or now
        if end < since:
            continue
        start = max(r["start"], since)
        dur = max(0.0, end - start)
        downtime += dur
        count += 1
        if r["end"]:
            durations.append(r["end"] - r["start"])
    availability = max(0.0, 1 - downtime / window_s)
    mttr = sum(durations) / len(durations) if durations else None
    uptime = window_s - downtime
    mtbf = uptime / count if count else None
    return {"window_days": round(window_s / 86400, 1), "availability": round(availability, 5),
            "incidents": count, "downtime_s": round(downtime), "mttr_s": round(mttr) if mttr else None,
            "mtbf_s": round(mtbf) if mtbf else None, "currently_down": _open_for(device_id) is not None}


async def _prom(query: str) -> list[dict]:
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(PROM + "/api/v1/query", params={"query": query})
            r.raise_for_status()
            return r.json().get("data", {}).get("result", [])
    except Exception as e:
        log.warning("prometheus query failed: %s", e)
        return []


async def latency_percentiles(device_id: str, window: str = "7d") -> list[dict]:
    """p5/p50/p95 of each check's latency over the window, straight from Prometheus."""
    out: dict[str, dict] = {}
    for q, key in ((0.05, "p5"), (0.5, "p50"), (0.95, "p95")):
        expr = 'quantile_over_time(%s, netops_check_latency_ms{device="%s"}[%s])' % (q, device_id, window)
        for row in await _prom(expr):
            check = row["metric"].get("check", "?")
            val = float(row["value"][1]) if row.get("value") else None
            out.setdefault(check, {"check": check})[key] = round(val, 1) if val is not None else None
    return sorted(out.values(), key=lambda r: r["check"])


async def summary(device_id: str, window_days: int = 7) -> dict:
    return {**_stats(device_id, window_days * 86400),
            "latency": await latency_percentiles(device_id, "%dd" % window_days)}


def fleet(window_days: int = 7) -> list[dict]:
    """Availability/MTTR per device, for a reliability overview (no Prometheus round-trips)."""
    from . import inventory
    w = window_days * 86400
    return [{"device": d.id, "device_name": d.name, **_stats(d.id, w)} for d in inventory.load()]
