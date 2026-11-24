"""Irrenhaus NetOps API: inventory, live status, config backups, alerts and Prometheus metrics."""
import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from . import (alerts, auth, backups, certs, db, exposure, features, features_api, honeypot, inventory, jobs,
               lifecycle, metrics, netmap, report, security, security_api, settings, state, vault)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    db.init()
    auth.ensure_setup_code()
    if features.enabled("honeypot"):
        await honeypot.start()
    tasks = [asyncio.create_task(jobs.watcher()), asyncio.create_task(jobs.backup_scheduler()),
             asyncio.create_task(security.scheduler()), asyncio.create_task(certs.scheduler()),
             asyncio.create_task(lifecycle.scheduler()), asyncio.create_task(exposure.scheduler()),
             asyncio.create_task(report.scheduler()), asyncio.create_task(netmap.scheduler())]
    yield
    for t in tasks:
        t.cancel()


app = FastAPI(title="Irrenhaus NetOps", lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json")
app.include_router(auth.router)
app.include_router(vault.router)
app.include_router(metrics.router)
app.include_router(security_api.router)
app.include_router(features_api.router)


# Writes need the X-NetOps header (a cross-site form or image can't set it: CSRF protection on top of the
# SameSite=Strict cookie) and, outside the account endpoints, an administrator. Exempt: signed one-click
# links from alerts and Grafana's webhook (container-internal).
_WRITE_EXEMPT = ("/api/security/act/", "/api/hooks/grafana")


@app.middleware("http")
async def guard(request: Request, call_next):
    path = request.url.path
    if request.method not in ("GET", "HEAD", "OPTIONS") and path.startswith("/api/") and not path.startswith(_WRITE_EXEMPT):
        if request.headers.get("x-netops") != "1":
            return JSONResponse({"detail": "missing X-NetOps header"}, status_code=403)
        if not path.startswith("/api/auth/"):
            s = auth.current_user(request)
            if not s:
                return JSONResponse({"detail": "not logged in"}, status_code=401)
            if s["role"] != "admin":
                return JSONResponse({"detail": "Only administrators can make changes."}, status_code=403)
    return await call_next(request)


def _device_or_404(device_id: str):
    dev = inventory.get(device_id)
    if not dev:
        raise HTTPException(404, "unknown device")
    return dev


def _device_view(dev) -> dict:
    latest = backups.latest(dev.id)
    return {**dev.public(), "state": state.get(dev.id).public(),
            "latest_backup": latest and {"version": latest["version"], "files": latest["files"]}}


@app.get("/api/health")
async def health():
    return {"ok": True, "time": time.time()}


@app.get("/api/summary")
async def summary():
    devs = inventory.load()
    counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
    for d in devs:
        counts[state.get(d.id).status] += 1
    with_backup = [d for d in devs if d.backup]
    return {
        "devices": len(devs), "status": counts,
        "backups": {"devices": len(with_backup),
                    "ok": sum(1 for d in with_backup if state.get(d.id).backup_ok),
                    "failed": sum(1 for d in with_backup if state.get(d.id).backup_ok is False)},
        "disk": backups.disk_usage(),
        "settings": {"check_interval": settings.CHECK_INTERVAL, "backup_time": settings.BACKUP_TIME,
                     "ntfy_topic": settings.NTFY_TOPIC},
    }


@app.get("/api/devices")
async def devices():
    return [_device_view(d) for d in inventory.load()]


@app.get("/api/devices/{device_id}")
async def device(device_id: str):
    return _device_view(_device_or_404(device_id))


@app.post("/api/devices/{device_id}/check")
async def check_now(device_id: str):
    dev = _device_or_404(device_id)
    await jobs.check_device(dev)
    return state.get(dev.id).public()


@app.get("/api/devices/{device_id}/backups")
async def device_backups(device_id: str):
    _device_or_404(device_id)
    return backups.versions(device_id)


@app.post("/api/devices/{device_id}/backup")
async def backup_now(device_id: str):
    dev = _device_or_404(device_id)
    try:
        return await jobs.backup_device(dev)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, "%s: %s" % (type(e).__name__, e))


@app.get("/api/devices/{device_id}/files/{filename}")
async def backup_file(device_id: str, filename: str, download: bool = False):
    _device_or_404(device_id)
    try:
        p = backups.path(device_id, filename)
    except FileNotFoundError:
        raise HTTPException(404, "no such file")
    if download or not filename.endswith((".rsc", ".json", ".txt", ".conf")):
        return FileResponse(p, filename="%s-%s" % (device_id, filename))
    return PlainTextResponse(p.read_text(errors="replace"))


@app.get("/api/devices/{device_id}/diff")
async def backup_diff(device_id: str, a: str, b: str):
    _device_or_404(device_id)
    if not (backups.VERSION_RE.match(a) and backups.VERSION_RE.match(b)):
        raise HTTPException(400, "bad version")
    try:
        return PlainTextResponse(backups.diff(device_id, a, b))
    except StopIteration:
        raise HTTPException(404, "no such version")


@app.get("/api/inbox")
async def inbox():
    return backups.inbox()


@app.get("/api/alerts")
async def recent_alerts(since: str = "24h"):
    return await alerts.recent(since)


@app.post("/api/alerts/test")
async def test_alert():
    await alerts.notify("Test alert", "If you can read this, ntfy alerts work.", "info")
    return {"sent": True}


@app.post("/api/hooks/grafana")
async def grafana_hook(request: Request):
    """Grafana contact point (webhook) -> one readable ntfy message per alert."""
    body = await request.json()
    for a in body.get("alerts", []):
        firing = a.get("status") == "firing"
        labels, ann = a.get("labels", {}), a.get("annotations", {})
        title = "%s %s" % (labels.get("alertname", "Grafana alert"), "firing" if firing else "resolved")
        msg = ann.get("summary") or ann.get("description") or body.get("message", "")
        level = labels.get("severity", "warning") if firing else "ok"
        await alerts.notify(title, msg, level, labels.get("device"))
    return {"ok": True}


@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
