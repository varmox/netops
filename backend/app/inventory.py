"""The device inventory: config/devices.yml, re-read whenever the file changes."""
import json
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

from . import settings


@dataclass
class Device:
    id: str
    name: str
    type: str                                   # mikrotik, zyxel, generic, ...
    host: str
    role: str = ""
    notes: str = ""
    checks: list[dict[str, Any]] = field(default_factory=list)
    backup: dict[str, Any] | None = None        # collector settings, or None for watch-only devices
    links: dict[str, str] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)   # free-form: model, MAC, firmware, location
    software: list[dict[str, Any]] = field(default_factory=list)   # [{cpe, version | version_from, kev}]
    protected: bool = False                     # never quarantine (router, modem, the NetOps host)
    alert: bool | None = None                   # page on down/degraded? None = only infrastructure (protected)
    ssh: dict[str, Any] | None = None           # linux hosts: {user, key, port}
    docker: bool = False                        # linux hosts: scan running container images with Trivy
    managed: bool = False                        # added/edited in the UI (lives in the /data store, not devices.yml)

    @property
    def alert_default(self) -> bool:
        """Alerting before any UI override: the yaml `alert:` field, else infrastructure
        (protected) only — a TV or a phone dropping off is normal, so it stays silent."""
        return self.protected if self.alert is None else self.alert

    @property
    def alert_on_down(self) -> bool:
        """Whether a down/degraded transition pages, after any UI override."""
        return _alert_overrides().get(self.id, self.alert_default)

    def public(self) -> dict[str, Any]:
        """What the API returns: everything except collector credentials."""
        backup = None
        if self.backup:
            backup = {k: v for k, v in self.backup.items() if k in ("method", "binary", "redact")}
        return {
            "id": self.id, "name": self.name, "type": self.type, "host": self.host, "role": self.role,
            "notes": self.notes, "checks": self.checks, "backup": backup, "links": self.links, "facts": self.facts,
            "software": self.software, "protected": self.protected, "docker": self.docker,
            "managed": self.managed,
            "alert_on_down": self.alert_on_down,
            "alert_default": self.alert_default,
            "alert_overridden": self.id in _alert_overrides(),
            "ssh": {k: v for k, v in (self.ssh or {}).items() if k in ("user", "port")} or None,
        }


def _normalize_check(c: Any) -> dict[str, Any]:
    # "ping" | {"tcp": 22} | {"http": "http://..."} | already-normalized {"type": .., "target": ..}
    if isinstance(c, str):
        return {"type": c}
    if "type" in c:                              # already normalized (e.g. from the UI / managed store)
        out = {"type": c["type"]}
        if c.get("target") not in (None, ""):
            out["target"] = c["target"]
        return out
    (kind, value), = c.items()
    return {"type": kind, "target": value}


_cache: tuple[tuple, list[Device]] | None = None


def _files() -> list:
    """devices.yml plus any config/devices.d/*.yml (e.g. a lab host you can delete without touching the main file)."""
    extra = settings.DEVICES_FILE.parent / "devices.d"
    return [settings.DEVICES_FILE] + (sorted(extra.glob("*.yml")) if extra.is_dir() else [])


def load() -> list[Device]:
    global _cache
    files = _files()
    mstamp = _MANAGED.stat().st_mtime if _MANAGED.is_file() else 0.0
    stamp = (tuple((str(f), f.stat().st_mtime) for f in files), mstamp)
    if _cache and _cache[0] == stamp:
        return _cache[1]
    devices = []
    for f in files:
        for d in (yaml.safe_load(f.read_text()) or {}).get("devices", []) or []:
            d = dict(d)
            d["checks"] = [_normalize_check(c) for c in d.get("checks", [])]
            devices.append(Device(**d))
    for d in _managed_devices().values():          # UI-managed devices (data/devices_managed.json)
        d = dict(d)
        d["checks"] = [_normalize_check(c) for c in d.get("checks", [])]
        devices.append(Device(**d, managed=True))
    ids = [d.id for d in devices]
    if len(ids) != len(set(ids)):
        raise ValueError("device ids must be unique across devices.yml and devices.d/")
    _cache = (stamp, devices)
    return devices


def get(device_id: str) -> Device | None:
    return next((d for d in load() if d.id == device_id), None)


# Per-device alerting overrides set from the UI, kept out of devices.yml so its comments and
# formatting stay pristine. {device_id: bool}; a missing key means "use the device default".
_ALERTS = settings.DATA_DIR / "device_alerts.json"


def _alert_overrides() -> dict[str, bool]:
    try:
        return json.loads(_ALERTS.read_text())
    except (OSError, ValueError):
        return {}


def set_alert(device_id: str, on: bool | None) -> None:
    """on True/False sets an explicit override; None clears it (back to the device default)."""
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    ov = _alert_overrides()
    if on is None:
        ov.pop(device_id, None)
    else:
        ov[device_id] = bool(on)
    tmp = _ALERTS.with_suffix(".tmp")
    tmp.write_text(json.dumps(ov, indent=1))
    tmp.replace(_ALERTS)


# Devices added/edited from the UI. Kept in /data (not devices.yml) so the hand-maintained YAML and its
# comments stay pristine, and so this works with a read-only config mount. {id: {device fields...}}.
_MANAGED = settings.DATA_DIR / "devices_managed.json"
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# What a managed device may set. ssh/backup are allowed but sanitized to connection settings only — a raw
# secret never lands in the store; credentials live in the vault, referenced by *_vault.
_MANAGED_FIELDS = ("id", "name", "type", "host", "role", "notes", "checks", "protected", "alert",
                   "links", "facts", "ssh", "backup")
_SSH_SAFE = ("user", "port", "key_vault")
_BACKUP_SAFE = ("method", "user", "key_vault", "password_vault", "binary", "redact", "scheme", "port")


def _sanitize(cfg: Any, allowed: tuple[str, ...]) -> dict | None:
    if not isinstance(cfg, dict):
        return None
    out = {k: cfg[k] for k in allowed if cfg.get(k) is not None}
    return out or None


def _managed_devices() -> dict[str, dict]:
    try:
        return json.loads(_MANAGED.read_text())
    except (OSError, ValueError):
        return {}


def _write_managed(data: dict[str, dict]) -> None:
    global _cache
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _MANAGED.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    tmp.replace(_MANAGED)
    _cache = None                                  # force load() to re-read


def save_device(spec: dict, creating: bool) -> "Device":
    """Create or update a UI-managed device. Raises ValueError on invalid input or an id clash."""
    dev_id = (spec.get("id") or "").strip()
    if not _ID_RE.match(dev_id):
        raise ValueError("id must be lowercase letters, digits or hyphens (max 64, starting alphanumeric)")
    if not (spec.get("name") or "").strip():
        raise ValueError("name is required")
    if not (spec.get("host") or "").strip():
        raise ValueError("host (IP or hostname) is required")
    managed = _managed_devices()
    if creating:
        if get(dev_id):
            raise ValueError("a device with id %r already exists" % dev_id)
    elif dev_id not in managed:
        raise ValueError("no managed device with id %r (devices.yml devices are read-only here)" % dev_id)
    clean = {k: spec[k] for k in _MANAGED_FIELDS if k in spec and spec[k] is not None}
    clean["id"] = dev_id
    clean["checks"] = [_normalize_check(c) for c in clean.get("checks", [])]
    if "ssh" in clean:
        clean["ssh"] = _sanitize(clean["ssh"], _SSH_SAFE)
    if "backup" in clean:
        clean["backup"] = _sanitize(clean["backup"], _BACKUP_SAFE)
    clean = {k: v for k, v in clean.items() if v is not None}
    managed[dev_id] = clean
    _write_managed(managed)
    dev = get(dev_id)
    assert dev is not None
    return dev


def patch_managed(device_id: str, patch: dict) -> "Device | None":
    """Merge connection settings (ssh/backup) into a managed device; a value of None removes that key.
    ssh/backup are sanitized so only connection settings (and *_vault refs) are ever stored."""
    managed = _managed_devices()
    if device_id not in managed:
        raise ValueError("not a managed device")
    dev = dict(managed[device_id])
    for k, v in patch.items():
        if k == "ssh":
            v = _sanitize(v, _SSH_SAFE)
        elif k == "backup":
            v = _sanitize(v, _BACKUP_SAFE)
        if v is None:
            dev.pop(k, None)
        else:
            dev[k] = v
    managed[device_id] = dev
    _write_managed(managed)
    return get(device_id)


def delete_device(device_id: str) -> bool:
    """Remove a UI-managed device. Returns False if it wasn't a managed device."""
    managed = _managed_devices()
    if device_id not in managed:
        return False
    managed.pop(device_id)
    _write_managed(managed)
    set_alert(device_id, None)                     # drop any orphaned alert override
    return True
