"""HTTP API for the Security page. /api/security/act/<token> is the only route reachable without a session:
the signed, expiring token in the link is the authorization (used by the buttons in ntfy alerts)."""
import asyncio
import logging

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from . import auth, remediation, security

router = APIRouter(prefix="/api/security")
_jobs: dict[str, asyncio.Task] = {}
log = logging.getLogger("netops.security")


def _log_result(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception():
        log.error("security job failed", exc_info=task.exception())
    elif not task.cancelled():
        log.info("security job done: %s", task.result())

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _mtime(path) -> float | None:
    return path.stat().st_mtime if path.is_file() else None


def _start(name: str, coro) -> bool:
    if name in _jobs and not _jobs[name].done():
        return False
    _jobs[name] = asyncio.create_task(coro)
    _jobs[name].add_done_callback(_log_result)
    return True


@router.get("/summary")
async def summary():
    f = list(security.load().values())
    open_ = [x for x in f if x["status"] in ("open", "acknowledged", "remediating")]
    return {
        "open": {s: sum(1 for x in open_ if x["severity"] == s) for s in SEVERITY_ORDER},
        "kev": sum(1 for x in open_ if x.get("kev")),
        "quarantined": sum(1 for x in f if x["status"] == "quarantined"),
        "resolved": sum(1 for x in f if x["status"] == "resolved"),
        # after a restart, fall back to when the files on disk were written
        "last_feeds": security.STATUS["feeds"] or _mtime(security.SEC_DIR / "kev.json"),
        "last_scan": security.STATUS["scan"] or security.services().get("time"),
        "running": {k: not t.done() for k, t in _jobs.items()}, "dry_run": remediation.DRY_RUN,
    }


@router.get("/findings")
async def findings():
    rows = sorted(security.load().values(),
                  key=lambda x: (x["status"] == "resolved", SEVERITY_ORDER.get(x["severity"], 9), -(x.get("score") or 0)))
    return [{**x, "proposals": remediation.proposals(x)} for x in rows]


class Act(BaseModel):
    action: str


@router.post("/findings/{finding_id:path}/action")
async def act(finding_id: str, body: Act, request: Request):
    user = (auth.current_user(request) or {}).get("username") or "?"
    try:
        return {"result": await remediation.execute(finding_id, body.action, user)}
    except KeyError:
        raise HTTPException(404, "unknown finding")
    except (PermissionError, ValueError) as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(502, "%s: %s" % (type(e).__name__, e))


@router.post("/sync")
async def sync():
    return {"started": _start("feeds", security.sync_feeds())}


@router.post("/scan")
async def scan():
    return {"started": _start("scan", security.scan_lan())}


@router.get("/services")
async def services():
    return security.services()


@router.get("/news")
async def news():
    return await security.news()


@router.get("/quarantine")
async def quarantine():
    try:
        return await remediation.quarantined()
    except Exception as e:
        raise HTTPException(502, str(e))


class Release(BaseModel):
    kind: str
    address: str


@router.post("/quarantine/release")
async def release(body: Release):
    try:
        if body.kind == "wifi":
            return {"result": await remediation.wifi_allow(body.address)}
        return {"result": await remediation.release(body.address)}
    except Exception as e:
        raise HTTPException(502, str(e))


@router.get("/audit")
async def audit():
    return remediation.audit_log()


@router.post("/act/{token}")
async def act_from_link(token: str):
    """Button in an ntfy alert (HTTP action): approve one specific action for one finding."""
    try:
        fid, action = remediation.verify_token(token)
        return {"result": await remediation.execute(fid, action, "ntfy link")}
    except PermissionError as e:
        raise HTTPException(403, str(e))


@router.get("/act/{token}", response_class=HTMLResponse)
async def act_page(token: str):
    """Opening the link in a browser shows what it would do instead of doing it."""
    try:
        fid, action = remediation.verify_token(token)
    except PermissionError as e:
        raise HTTPException(403, str(e))
    return ("<!doctype html><meta name=viewport content='width=device-width'><body style='font-family:sans-serif;padding:2rem'>"
            "<h3>%s</h3><p>Finding: <code>%s</code></p><form method=post><button style='font-size:1.1rem;padding:.6rem 1.2rem'>"
            "Confirm</button></form></body>" % (remediation.LABELS.get(action, action), fid))
