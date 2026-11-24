"""Background jobs: the health watcher (every CHECK_INTERVAL) and the daily config backup."""
import asyncio
import logging
import time
from datetime import datetime, timedelta

from prometheus_client import Counter, Gauge

from . import alerts, backups, checks, features, inventory, reliability, settings, state
from .collectors import COLLECTORS

log = logging.getLogger("netops.jobs")

UP = Gauge("netops_device_up", "1 up, 0.5 degraded, 0 down", ["device"])
CHECK_OK = Gauge("netops_check_ok", "Result of one check", ["device", "check"])
CHECK_MS = Gauge("netops_check_latency_ms", "Latency of one check", ["device", "check"])
BACKUP_OK = Gauge("netops_backup_ok", "1 if the last backup run succeeded", ["device"])
BACKUP_LAST = Gauge("netops_backup_last_success_timestamp", "Unix time of the last successful backup", ["device"])
CHANGES = Counter("netops_config_changes_total", "Config changes detected by backups", ["device"])

LEVEL_VALUE = {"up": 1.0, "degraded": 0.5, "down": 0.0}


async def check_device(dev) -> None:
    st = state.get(dev.id)
    results = await asyncio.gather(*(checks.run(dev.host, c) for c in dev.checks))
    st.checks = []
    for c, (ok, ms, detail) in zip(dev.checks, results):
        name = checks.label(c)
        st.checks.append({"check": name, "ok": ok, "latency_ms": ms, "detail": detail})
        CHECK_OK.labels(dev.id, name).set(1 if ok else 0)
        if ms is not None:
            CHECK_MS.labels(dev.id, name).set(ms)
    st.last_check = time.time()

    n_ok = sum(1 for ok, _, _ in results if ok)
    if not results:
        return
    if n_ok == len(results):
        new, st.fails = "up", 0
    elif n_ok:
        new, st.fails = "degraded", 0
    else:
        st.fails += 1
        new = "down" if st.fails >= settings.FAILS_BEFORE_DOWN else st.status
    UP.labels(dev.id).set(LEVEL_VALUE.get(new, 0))
    if new == st.status:
        return

    old, st.status, st.since = st.status, new, time.time()
    # Record downtime incidents (reliability: availability, MTTR, MTBF).
    if new in ("down", "degraded") and old not in ("down", "degraded"):
        reliability.incident_open(dev.id)
    elif new == "up" and old in ("down", "degraded"):
        reliability.incident_close(dev.id)
    failed = ", ".join("%s (%s)" % (c["check"], c["detail"]) for c in st.checks if not c["ok"]) or "-"
    if not dev.alert_on_down:
        return  # tracked for uptime, but this device doesn't page (e.g. a TV, a phone)
    if new == "down":
        await alerts.notify("%s is DOWN" % dev.name, "%s (%s) stopped answering: %s" % (dev.name, dev.host, failed),
                            "critical", dev.id)
    elif new == "degraded":
        await alerts.notify("%s is degraded" % dev.name, "Failing checks on %s: %s" % (dev.host, failed),
                            "warning", dev.id)
    elif new == "up" and old in ("down", "degraded"):
        await alerts.notify("%s is back up" % dev.name, "All checks on %s pass again." % dev.host, "ok", dev.id)


async def watcher() -> None:
    while True:
        if features.enabled("health"):
            try:
                await asyncio.gather(*(check_device(d) for d in inventory.load()))
            except Exception:  # keep watching even if one round blows up (e.g. a broken devices.yml)
                log.exception("check round failed")
        await asyncio.sleep(settings.CHECK_INTERVAL)


async def backup_device(dev) -> dict:
    st = state.get(dev.id)
    if not dev.backup or dev.backup.get("method") not in COLLECTORS:
        raise ValueError("%s has no backup method" % dev.id)
    if st.backup_running:
        raise RuntimeError("a backup of %s is already running" % dev.id)
    st.backup_running, st.backup_last_run = True, time.time()
    try:
        files = await COLLECTORS[dev.backup["method"]](dev, dev.backup)
        meta, changed = backups.store(dev.id, files)
    except Exception as e:
        st.backup_ok, st.backup_error = False, "%s: %s" % (type(e).__name__, e)
        BACKUP_OK.labels(dev.id).set(0)
        await alerts.notify("Backup of %s failed" % dev.name, st.backup_error, "warning", dev.id)
        raise
    finally:
        st.backup_running = False
    st.backup_ok, st.backup_error, st.backup_last_ok = True, None, time.time()
    backups.record_success(dev.id, st.backup_last_ok)
    BACKUP_OK.labels(dev.id).set(1)
    BACKUP_LAST.labels(dev.id).set(st.backup_last_ok)
    if changed and meta.get("previous"):
        CHANGES.labels(dev.id).inc()
        ds = meta.get("diffstat", {})
        await alerts.notify("Config of %s changed" % dev.name,
                            "New version %s: +%d / -%d lines." % (meta["version"], ds.get("added", 0),
                                                                  ds.get("removed", 0)), "info", dev.id)
    return {"version": meta["version"], "changed": changed}


async def backup_all() -> None:
    for dev in inventory.load():
        if dev.backup:
            try:
                await backup_device(dev)
            except Exception:
                log.exception("backup of %s failed", dev.id)


def _seconds_until(hhmm: str) -> float:
    h, m = (int(x) for x in hhmm.split(":"))
    now = datetime.now()
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += timedelta(days=1)
    return (nxt - now).total_seconds()


def restore_backup_state() -> None:
    """After a restart: take the last successful run from disk, so status and metrics don't start empty."""
    for dev in inventory.load():
        when = backups.last_success(dev.id) if dev.backup else None
        if when:
            st = state.get(dev.id)
            st.backup_ok, st.backup_last_ok = True, when
            BACKUP_OK.labels(dev.id).set(1)
            BACKUP_LAST.labels(dev.id).set(when)


async def backup_scheduler() -> None:
    restore_backup_state()
    # Catch up after a restart: back up any device without a successful run in the last 24 hours.
    await asyncio.sleep(20)
    for dev in inventory.load():
        last = backups.last_success(dev.id) if dev.backup else None
        if dev.backup and (last is None or time.time() - last > 86400):
            try:
                await backup_device(dev)
            except Exception:
                log.exception("initial backup of %s failed", dev.id)
    while True:
        await asyncio.sleep(_seconds_until(settings.BACKUP_TIME))
        if features.enabled("backups"):
            await backup_all()
