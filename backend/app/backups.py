"""Versioned config storage: <BACKUP_DIR>/<device>/<version>.<suffix> plus <version>.meta.json.

A new version is only written when the comparable part of the config changed, so the history is a list
of real changes. Versions are UTC timestamps (20261123T031500Z), which sort by name.
"""
import difflib
import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import settings

VERSION_RE = re.compile(r"^\d{8}T\d{6}Z$")
FILE_RE = re.compile(r"^\d{8}T\d{6}Z\.[a-z]+$")


def device_dir(device_id: str) -> Path:
    return settings.BACKUP_DIR / device_id


def versions(device_id: str) -> list[dict]:
    d = device_dir(device_id)
    if not d.is_dir():
        return []
    out = []
    for meta in sorted(d.glob("*.meta.json"), reverse=True):
        m = json.loads(meta.read_text())
        out.append(m)
    return out


def latest(device_id: str) -> dict | None:
    v = versions(device_id)
    return v[0] if v else None


def store(device_id: str, files: list[tuple[str, bytes, str | None]]) -> tuple[dict, bool]:
    """Write a new version if the config changed. Returns (version meta, changed)."""
    primary_suffix, primary, comparable = files[0]
    digest = hashlib.sha256((comparable if comparable is not None else primary.decode(errors="replace"))
                            .encode()).hexdigest()
    prev = latest(device_id)
    if prev and prev["hash"] == digest:
        return prev, False

    version = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    d = device_dir(device_id)
    d.mkdir(parents=True, exist_ok=True)
    names = []
    for suffix, data, _ in files:
        name = "%s.%s" % (version, suffix)
        (d / name).write_bytes(data)
        names.append({"name": name, "size": len(data), "text": suffix in ("rsc", "json", "txt", "conf")})
    meta = {"version": version, "hash": digest, "files": names, "primary": "%s.%s" % (version, primary_suffix),
            "previous": prev["version"] if prev else None}
    if prev:
        meta["diffstat"] = _diffstat(read(device_id, prev["primary"]), primary.decode(errors="replace"))
    (d / ("%s.meta.json" % version)).write_text(json.dumps(meta, indent=1))
    _prune(device_id)
    return meta, True


def record_success(device_id: str, when: float) -> None:
    """Every successful run counts, changed or not; kept on disk so a restart doesn't forget it."""
    d = device_dir(device_id)
    d.mkdir(parents=True, exist_ok=True)
    (d / "last_success.json").write_text(json.dumps({"time": when}))


def last_success(device_id: str) -> float | None:
    p = device_dir(device_id) / "last_success.json"
    return json.loads(p.read_text())["time"] if p.is_file() else None


def _prune(device_id: str) -> None:
    for old in versions(device_id)[settings.BACKUP_KEEP:]:
        for f in device_dir(device_id).glob(old["version"] + ".*"):
            f.unlink()


def read(device_id: str, filename: str) -> str:
    return path(device_id, filename).read_text(errors="replace")


def path(device_id: str, filename: str) -> Path:
    if not FILE_RE.match(filename):
        raise FileNotFoundError(filename)
    p = device_dir(device_id) / filename
    if not p.is_file():
        raise FileNotFoundError(filename)
    return p


def _diffstat(a: str, b: str) -> dict:
    added = removed = 0
    for line in difflib.unified_diff(a.splitlines(), b.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return {"added": added, "removed": removed}


def diff(device_id: str, a: str, b: str) -> str:
    ma = next(v for v in versions(device_id) if v["version"] == a)
    mb = next(v for v in versions(device_id) if v["version"] == b)
    return "\n".join(difflib.unified_diff(
        read(device_id, ma["primary"]).splitlines(), read(device_id, mb["primary"]).splitlines(),
        fromfile=ma["primary"], tofile=mb["primary"], lineterm=""))


def inbox() -> list[dict]:
    """Files uploaded over SFTP (device pushes, the Zyxel's official backup, ...)."""
    root = settings.INBOX_DIR
    if not root.is_dir():
        return []
    out = []
    for f in sorted(root.rglob("*")):
        if f.is_file():
            st = f.stat()
            out.append({"name": str(f.relative_to(root)), "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()})
    return out


def disk_usage() -> dict:
    u = shutil.disk_usage(settings.DATA_DIR)
    return {"total": u.total, "free": u.free}
