from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


STATE_VERSION = 1
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class ServiceStateError(Exception):
    """Raised when dynamically managed service state cannot be loaded or saved."""


def state_file() -> Path:
    configured = os.getenv("MODEL_MANAGER_SERVICE_STATE_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    data_dir = os.getenv("DATA_DIR")
    base = Path(data_dir).expanduser().resolve() if data_dir else PLUGIN_ROOT / "data"
    return base / "model-manager-services.json"


def empty_state() -> dict[str, Any]:
    return {"version": STATE_VERSION, "services": {}, "removed": []}


def load_state(path: Path | None = None) -> dict[str, Any]:
    source = path or state_file()
    if not source.exists():
        return empty_state()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ServiceStateError(f"cannot read service state {source}: {exc}") from exc
    return normalize_state(raw)


def normalize_state(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ServiceStateError("service state must be an object")
    services_raw = raw.get("services", {})
    if not isinstance(services_raw, dict):
        raise ServiceStateError("service state 'services' must be an object")
    services: dict[str, dict[str, Any]] = {}
    for name, item in services_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise ServiceStateError("service state has an invalid service name")
        if not isinstance(item, dict):
            raise ServiceStateError(f"service state {name!r} must be an object")
        services[name.strip()] = dict(item)
    removed_raw = raw.get("removed", [])
    if not isinstance(removed_raw, list):
        raise ServiceStateError("service state 'removed' must be an array")
    removed: list[str] = []
    for item in removed_raw:
        name = str(item).strip()
        if name and name not in removed:
            removed.append(name)
    return {
        "version": STATE_VERSION,
        "services": services,
        "removed": sorted(removed),
    }


def save_state(state: Mapping[str, Any], path: Path | None = None) -> None:
    target = path or state_file()
    normalized = normalize_state(state)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ServiceStateError(f"cannot write service state {target}: {exc}") from exc
