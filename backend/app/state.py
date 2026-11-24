"""Live state of every device (in memory; rebuilt by the first check round after a restart)."""
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DeviceState:
    status: str = "unknown"            # up, degraded, down, unknown
    fails: int = 0                     # consecutive rounds with every check failing
    since: float | None = None         # when the current status began
    last_check: float | None = None
    checks: list[dict[str, Any]] = field(default_factory=list)
    backup_ok: bool | None = None
    backup_last_run: float | None = None
    backup_last_ok: float | None = None
    backup_error: str | None = None
    backup_running: bool = False

    def public(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "fails"}


STATES: dict[str, DeviceState] = {}


def get(device_id: str) -> DeviceState:
    return STATES.setdefault(device_id, DeviceState())
