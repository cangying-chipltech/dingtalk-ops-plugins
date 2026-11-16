from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence


MANAGEMENT_VERSION = 1
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class AlertManagementError(Exception):
    """Raised when alert management state cannot be loaded or applied."""


def management_file() -> Path:
    configured = os.getenv("MODEL_MANAGER_ALERT_STATE_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    data_dir = os.getenv("DATA_DIR")
    base = Path(data_dir).expanduser().resolve() if data_dir else PLUGIN_ROOT / "data"
    return base / "model-manager-alert-management.json"


def empty_management() -> dict[str, Any]:
    return {
        "version": MANAGEMENT_VERSION,
        "disabled": [],
        "removed": [],
        "added": {},
    }


def load_management(path: Path | None = None) -> dict[str, Any]:
    source = path or management_file()
    if not source.exists():
        return empty_management()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AlertManagementError(
            f"cannot read alert management file {source}: {exc}"
        ) from exc
    return normalize_management(raw)


def normalize_management(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AlertManagementError("alert management state must be an object")
    added_raw = raw.get("added", {})
    if not isinstance(added_raw, dict):
        raise AlertManagementError("alert management 'added' must be an object")
    added: dict[str, dict[str, Any]] = {}
    for name, item in added_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise AlertManagementError("alert management 'added' has an invalid name")
        if not isinstance(item, dict):
            raise AlertManagementError(
                f"managed alert {name!r} must be an object"
            )
        added[name.strip()] = dict(item)
    return {
        "version": MANAGEMENT_VERSION,
        "disabled": _name_list(raw.get("disabled"), "disabled"),
        "removed": _name_list(raw.get("removed"), "removed"),
        "added": added,
    }


def save_management(path: Path | None, state: Mapping[str, Any]) -> None:
    target = path or management_file()
    normalized = normalize_management(state)
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
        raise AlertManagementError(
            f"cannot write alert management file {target}: {exc}"
        ) from exc


def apply_management(
    monitors: Mapping[str, Any],
    state: Mapping[str, Any],
    *,
    monitor_type: str | None = None,
    exclude_type: str | None = None,
) -> dict[str, Any]:
    normalized = normalize_management(state)
    result = {name: item for name, item in monitors.items()}
    removed = set(normalized["removed"])

    for name, item in normalized["added"].items():
        item_type = _monitor_type(item)
        if monitor_type is not None and item_type != monitor_type:
            continue
        if exclude_type is not None and item_type == exclude_type:
            continue
        if name in result and name not in removed:
            raise AlertManagementError(
                f"managed alert {name!r} conflicts with an existing monitor"
            )
        result[name] = item

    for name in removed:
        result.pop(name, None)

    for name in normalized["disabled"]:
        item = result.get(name)
        if item is None:
            continue
        if not isinstance(item, dict):
            raise AlertManagementError(f"alert {name!r} must be an object")
        patched = dict(item)
        patched["enabled"] = False
        result[name] = patched
    return result


def clean_names(values: Sequence[str]) -> tuple[str, ...]:
    names: list[str] = []
    for value in values:
        for name in str(value).split(","):
            cleaned = name.strip()
            if cleaned and cleaned not in names:
                names.append(cleaned)
    return tuple(names)


def _monitor_type(item: Any) -> str:
    if not isinstance(item, Mapping):
        return ""
    check = item.get("check")
    if not isinstance(check, Mapping):
        return ""
    return str(check.get("type", "")).strip().lower()


def _name_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise AlertManagementError(f"alert management '{label}' must be an array")
    names: list[str] = []
    for item in value:
        name = str(item).strip()
        if name and name not in names:
            names.append(name)
    return sorted(names)
