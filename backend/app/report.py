"""Weekly report (feature 9): one digest of the week, pushed to ntfy and kept for the dashboard.

Pulls together what already exists — findings, updates applied (remediation audit log), backup status,
certificate and end-of-life warnings, honeypot hits, internet exposure and, if the host playbook wrote one,
the OpenSCAP compliance score. New devices are found by diffing the inventory against last week's snapshot.
"""
import json
import logging
import time

from . import alerts, backups, certs, exposure, honeypot, inventory, lifecycle, security, settings, state

log = logging.getLogger("netops.report")

DIR = settings.DATA_DIR / "reports"
LATEST = DIR / "latest.json"
SNAPSHOT = DIR / "devices.json"
WEEK = 7 * 86400


def _prev_device_ids() -> set[str]:
    return set(json.loads(SNAPSHOT.read_text())) if SNAPSHOT.is_file() else set()


def _compliance() -> dict | None:
    p = settings.COMPLIANCE_DIR / "summary.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text())
    except Exception:
        return None
    out = {}
    for name, c in (data.get("profiles") or {}).items():
        total = (c.get("pass", 0) + c.get("fail", 0)) or 1
        out[name] = {"pass": c.get("pass", 0), "fail": c.get("fail", 0),
                     "score": round(100 * c.get("pass", 0) / total)}
    return {"date": data.get("date"), "profiles": out}


def build() -> dict:
    devices = inventory.load()
    ids = {d.id for d in devices}
    new_ids = ids - _prev_device_ids()
    findings = list(security.load().values())
    open_f = [f for f in findings if f["status"] in ("open", "acknowledged", "remediating")]
    sev = {s: sum(1 for f in open_f if f["severity"] == s) for s in ("critical", "high", "medium", "low")}

    since = time.time() - WEEK
    from . import remediation
    updates = [a for a in remediation.audit_log(1000)
               if a.get("time", 0) >= since and a.get("action") in
               ("apply-updates", "update-container", "update-routeros", "quarantine", "wifi-disconnect")]

    cert_state = certs.load()
    cert_warn = [c for c in cert_state.get("certs", [])
                 if c.get("expires") and (c["expires"] - time.time()) / 86400 <= 30]
    eol = [d for d in lifecycle.load().get("devices", []) if d.get("status") in ("eol", "warn")]
    hp = [h for h in honeypot.hits(1000) if h.get("time", 0) >= since]
    exp = exposure.load()

    down = [d.name for d in devices if state.get(d.id).status == "down"]
    backup_fail = [d.name for d in devices if d.backup and state.get(d.id).backup_ok is False]

    report = {
        "time": time.time(),
        "window_days": 7,
        "devices": len(devices),
        "new_devices": [{"id": i, "name": next((d.name for d in devices if d.id == i), i)} for i in sorted(new_ids)],
        "findings_open": sev,
        "kev": sum(1 for f in open_f if f.get("kev")),
        "updates_applied": len(updates),
        "down": down,
        "backups_failing": backup_fail,
        "certs_expiring": [{"device": c["device_name"], "days": int((c["expires"] - time.time()) / 86400)}
                           for c in cert_warn],
        "end_of_life": [{"device": e["device_name"], "product": e["product"], "status": e["status"]} for e in eol],
        "honeypot_hits": len(hp),
        "exposures": len(exp.get("exposures", [])),
        "upnp_enabled": exp.get("upnp_enabled"),
        "compliance": _compliance(),
    }
    DIR.mkdir(parents=True, exist_ok=True)
    LATEST.write_text(json.dumps(report, indent=1))
    SNAPSHOT.write_text(json.dumps(sorted(ids)))
    return report


def as_text(r: dict) -> str:
    sev = r["findings_open"]
    lines = [
        "NetOps weekly report — %d devices" % r["devices"],
        "Open findings: %d critical, %d high, %d medium (%d actively exploited)" % (
            sev["critical"], sev["high"], sev["medium"], r["kev"]),
        "Updates/actions applied this week: %d" % r["updates_applied"],
    ]
    if r["new_devices"]:
        lines.append("New devices: " + ", ".join(d["name"] for d in r["new_devices"]))
    if r["down"]:
        lines.append("Down now: " + ", ".join(r["down"]))
    if r["backups_failing"]:
        lines.append("Backups failing: " + ", ".join(r["backups_failing"]))
    if r["certs_expiring"]:
        lines.append("Certificates expiring: " + ", ".join("%s (%dd)" % (c["device"], c["days"]) for c in r["certs_expiring"]))
    if r["end_of_life"]:
        lines.append("End-of-life: " + ", ".join(e["device"] for e in r["end_of_life"]))
    if r["honeypot_hits"]:
        lines.append("Honeypot hits: %d" % r["honeypot_hits"])
    if r["upnp_enabled"]:
        lines.append("UPnP is enabled; %d exposure(s) seen" % r["exposures"])
    if r["compliance"]:
        for name, c in r["compliance"]["profiles"].items():
            lines.append("Compliance %s: %d%% (%d pass / %d fail)" % (name, c["score"], c["pass"], c["fail"]))
    return "\n".join(lines)


def latest() -> dict | None:
    return json.loads(LATEST.read_text()) if LATEST.is_file() else None


async def send() -> dict:
    r = build()
    level = "warning" if (r["findings_open"]["critical"] or r["kev"] or r["down"]) else "info"
    await alerts.notify("NetOps weekly report", as_text(r), level)
    return r


async def scheduler() -> None:
    import asyncio
    from datetime import datetime, timedelta
    await asyncio.sleep(120)
    while True:
        now = datetime.now()
        h, m = (int(x) for x in settings.REPORT_TIME.split(":"))
        target = now.replace(hour=h, minute=m, second=0, microsecond=0)
        days_ahead = (settings.REPORT_DAY - now.weekday()) % 7
        target += timedelta(days=days_ahead)
        if target <= now:
            target += timedelta(days=7)
        await asyncio.sleep((target - now).total_seconds())
        from . import features
        if features.enabled("report"):
            try:
                await send()
            except Exception:
                log.exception("weekly report failed")
