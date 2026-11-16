from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


STATE_VERSION = 1
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


class ModelStateError(Exception):
    """Raised when dynamically added model state cannot be loaded or saved."""


def state_file() -> Path:
    configured = os.getenv("MODEL_MANAGER_MODEL_STATE_FILE")
    if configured:
        return Path(configured).expanduser().resolve()
    data_dir = os.getenv("DATA_DIR")
    base = Path(data_dir).expanduser().resolve() if data_dir else PLUGIN_ROOT / "data"
    return base / "model-manager-models.json"


def load_models(path: Path | None = None) -> dict[str, dict[str, Any]]:
    source = path or state_file()
    if not source.exists():
        return {}
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelStateError(f"cannot read model state {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ModelStateError("model state must be an object")
    models_raw = raw.get("models", {})
    if not isinstance(models_raw, dict):
        raise ModelStateError("model state 'models' must be an object")
    models: dict[str, dict[str, Any]] = {}
    for name, item in models_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise ModelStateError("model state has an invalid model name")
        if not isinstance(item, dict):
            raise ModelStateError(f"model state {name!r} must be an object")
        models[name.strip()] = dict(item)
    return models


def save_models(models: Mapping[str, Any], path: Path | None = None) -> None:
    target = path or state_file()
    normalized: dict[str, dict[str, Any]] = {}
    for name, item in models.items():
        if not isinstance(name, str) or not name.strip():
            raise ModelStateError("model state has an invalid model name")
        if not isinstance(item, Mapping):
            raise ModelStateError(f"model state {name!r} must be an object")
        normalized[name.strip()] = dict(item)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(
                {"version": STATE_VERSION, "models": normalized},
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise ModelStateError(f"cannot write model state {target}: {exc}") from exc
