"""Alerts go to ntfy; the web UI and phones subscribe to the same topic."""
import json
import logging

import httpx

from . import settings

log = logging.getLogger("netops.alerts")

PRIORITY = {"info": 3, "warning": 4, "critical": 5, "ok": 3}
TAGS = {"info": "information_source", "warning": "warning", "critical": "rotating_light", "ok": "white_check_mark"}


async def notify(title: str, message: str, level: str = "info", device: str | None = None,
                 actions: list[tuple[str, str, str]] | None = None) -> None:
    """actions: up to 3 ntfy buttons, ("view" | "http", label, url); http buttons POST to the url.

    Published as JSON (not headers), so titles like "MikroTik hAP ax³" survive: HTTP headers are ASCII-only.
    """
    body = {
        "topic": settings.NTFY_TOPIC, "title": title, "message": message,
        "priority": PRIORITY.get(level, 3), "tags": [t for t in (TAGS.get(level), device) if t],
    }
    if actions:
        body["actions"] = [
            {"action": kind, "label": label, "url": url, **({"method": "POST", "clear": True} if kind == "http" else {})}
            for kind, label, url in actions[:3]]
    headers = {"Authorization": "Bearer " + settings.NTFY_TOKEN} if settings.NTFY_TOKEN else {}
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.post(settings.NTFY_URL, json=body, headers=headers)
            r.raise_for_status()
    except Exception as e:
        # Alerting must never take the caller (watcher, backup, scan) down with it.
        log.warning("ntfy publish failed (%s): %s", e, title)


async def recent(since: str = "24h") -> list[dict]:
    """Messages still in ntfy's cache, newest first."""
    headers = {"Authorization": "Bearer " + settings.NTFY_TOKEN} if settings.NTFY_TOKEN else {}
    url = "%s/%s/json" % (settings.NTFY_URL, settings.NTFY_TOPIC)
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(url, params={"poll": "1", "since": since}, headers=headers)
            r.raise_for_status()
    except httpx.HTTPError as e:
        log.warning("ntfy poll failed: %s", e)
        return []
    msgs = [json.loads(line) for line in r.text.splitlines() if line.strip()]
    return sorted((m for m in msgs if m.get("event") == "message"), key=lambda m: m["time"], reverse=True)
