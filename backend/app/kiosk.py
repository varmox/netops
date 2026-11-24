"""A short, revocable share token for the read-only family/status view, so a wall display can show it
without a login. The token is a bearer secret: anyone with the URL sees the (non-technical, read-only)
status, which is exactly the point. Only the family summary is ever served through it — never the rest of
the API. Rotating the token instantly invalidates the old link.
"""
import json
import secrets
import time

from . import settings

_FILE = settings.DATA_DIR / "kiosk.json"
# Unambiguous alphabet (no 0/o/1/l/i) so a short code is easy to read off a screen and type into a display.
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_LEN = 8


def _load() -> dict:
    try:
        return json.loads(_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(data: dict) -> None:
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(_FILE)


def token() -> str | None:
    """The active token, or None if none is set / the link is disabled."""
    d = _load()
    return d.get("token") if d.get("enabled", True) else None


def config() -> dict:
    d = _load()
    tok = token()
    return {"enabled": bool(tok), "token": tok, "created": d.get("created")}


def rotate() -> str:
    """Generate a fresh token (invalidating any old one) and enable the link."""
    tok = "".join(secrets.choice(_ALPHABET) for _ in range(_LEN))
    _save({"token": tok, "created": time.time(), "enabled": True})
    return tok


def disable() -> None:
    d = _load()
    d["enabled"] = False
    _save(d)


def valid(candidate: str) -> bool:
    cur = token()
    return bool(cur) and secrets.compare_digest(candidate, cur)
