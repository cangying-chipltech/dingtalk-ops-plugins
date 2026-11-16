from __future__ import annotations

import json
import os
import re
import shlex
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from dingtalk_ops_bridge.plugin_api import (
    PLUGIN_API_VERSION,
    RESOURCE_CONFIG_DIR,
    ActionContext,
    ActionDefinition,
    ActionValidationError,
    PreparedAction,
)


DEFAULT_REMOTE_DIR = "/mnt/jfs/tools/swe-runner"
NODES_SERVICE = "nodes"
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STATUS_COMMANDS = {"status", "query", "s", "q"}
STATUS_COMMANDS = DEFAULT_STATUS_COMMANDS | {"check"}
HISTORY_COMMANDS = {"history", "historical", "recent", "details", "detail"}
HELP_COMMANDS = {"help", "?", "/help", "h", "帮助"}
FRAMEWORK_COMMANDS = {
    "help",
    "?",
    "/help",
    "h",
    "帮助",
    "list",
    "actions",
    "动作",
    "列表",
    "run",
    "exec",
    "execute",
    "执行",
    "batch",
    "批处理",
    "monitor",
    "监控",
    "nodes",
    "node",
    "节点",
    "check",
    "检查",
}
STRICT_HOST_KEY_VALUES = {"yes", "no", "accept-new"}
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SweRunnerError(ActionValidationError):
    """Raised when swe-runner config or execution fails."""


@dataclass(frozen=True)
class SweTarget:
    name: str
    queue: str
    node: str | None = None
    host: str | None = None
    user: str | None = None
    password_env: str | None = None
    remote_dir: str = DEFAULT_REMOTE_DIR
    aliases: tuple[str, ...] = ()
    port: int = 22
    strict_host_key_checking: str = "accept-new"

    def remote_command(self, history: bool) -> str:
        suffix = " --history" if history else ""
        return (
            f"cd {shlex.quote(self.remote_dir)} && "
            f"./status_swebench.sh {shlex.quote(self.queue)} --verbose{suffix}"
        )


@dataclass(frozen=True)
class SweRunnerSettings:
    raw_lines: int = 120
    timeout_seconds: float = 30.0
    max_output_chars: int = 8000
    max_reply_chars: int = 12000


@dataclass(frozen=True)
class SweRunnerCatalog:
    default: str | None
    targets: Mapping[str, SweTarget] = field(default_factory=dict)
    settings: SweRunnerSettings = field(default_factory=SweRunnerSettings)

    def resolve(self, token: str) -> SweTarget | None:
        wanted = token.lower()
        for name, target in self.targets.items():
            if name.lower() == wanted or any(alias.lower() == wanted for alias in target.aliases):
                return target
        return None

    def default_target(self) -> SweTarget | None:
        return self.targets.get(self.default) if self.default else None


class SweRunnerActionProvider:
    api_version = PLUGIN_API_VERSION
    type_name = "swe-runner"

    def validate(self, definition: ActionDefinition) -> None:
        _optional_string(definition.config.get("target"))
        _as_bool(definition.config.get("history", False), f"action {definition.name}.history")

    def prepare(
        self,
        definition: ActionDefinition,
        values: Mapping[str, str],
        context: ActionContext,
    ) -> PreparedAction:
        catalog = _load_catalog(context)
        if not catalog.targets:
            raise ActionValidationError(
                "swe-runner action requires a swe-runner config with at least one target"
            )
        resolved = definition.resolved_values(values)
        target_name = resolved.get("target") or _optional_string(definition.config.get("target"))
        target = catalog.resolve(target_name) if target_name else catalog.default_target()
        if target is None:
            raise ActionValidationError(f"unknown swe-runner target: {target_name or catalog.default or '-'!r}")

        history = _as_bool(definition.config.get("history", False), f"action {definition.name}.history")
        command, env, _ = _target_command(
            target,
            target.remote_command(history),
            context,
            materialize_password=False,
        )
        return PreparedAction(
            definition=definition,
            command=command,
            env={**definition.env, **env},
        )


class SweRunnerCommandProvider:
    api_version = PLUGIN_API_VERSION
    command_prefixes = ("swe-runner",)
    command_fallback = True

    def handle(self, prompt: str, context: ActionContext) -> str | None:
        text = (prompt or "").strip()
        forced = False
        lower = text.lower()
        if lower == "swe-runner":
            text = ""
            forced = True
        elif lower.startswith("swe-runner "):
            text = text[len("swe-runner") :].strip()
            forced = True

        if not text:
            return _format_help(_load_catalog(context)) if forced else None

        parts = text.split(maxsplit=1)
        first = parts[0]
        rest = parts[1] if len(parts) > 1 else ""
        command = first.lower()

        if not forced:
            if command in FRAMEWORK_COMMANDS:
                return None

        catalog = _load_catalog(context)
        if forced and command in HELP_COMMANDS:
            return self.help(f"swe-runner {text}".strip(), context) or _format_help(catalog)
        target = catalog.resolve(first)
        if target is not None:
            return _handle_target(target, rest, catalog, context)
        if forced and command in STATUS_COMMANDS:
            default = catalog.default_target()
            if default is None:
                raise SweRunnerError(
                    "需要先配置 swe-runner 默认目标或指定目标；"
                    "监控检查请使用 check 或 bridge status。"
                )
            return _run_status(default, command in HISTORY_COMMANDS, catalog.settings, context)
        if forced and command in HISTORY_COMMANDS:
            default = catalog.default_target()
            if default is None:
                raise SweRunnerError(
                    "history 需要先配置 swe-runner 默认目标；"
                    "监控检查请使用 check 或 bridge status。"
                )
            return _run_status(default, True, catalog.settings, context)
        if forced:
            return _format_help(catalog)
        return None

    def help(self, topic: str, context: ActionContext) -> str | None:
        text = (topic or "").strip()
        catalog = _load_catalog(context)
        parts = text.split()
        if parts and parts[0].casefold() == "swe-runner":
            parts = parts[1:]
        if not parts:
            return _format_help(catalog)
        if parts[0].casefold() in HELP_COMMANDS:
            parts = parts[1:]
            if not parts:
                return _format_help(catalog)
        command = parts[0].casefold()
        if command in STATUS_COMMANDS or command in HISTORY_COMMANDS:
            return _format_swe_help(catalog)
        target = catalog.resolve(parts[0])
        if target is not None:
            return _format_target_help(target)
        return None

    def help_lines(self) -> Sequence[str]:
        return (
            "- `swe-runner status|query|s|q`：默认目标状态",
            "- `swe-runner history|recent|details`：默认目标历史",
            "- `swe-runner <目标> status|history`：按目标 key 或别名查询",
            "- `<目标> status|history`：兼容旧 bridge 的目标优先写法",
            "- `swe-runner help`：swe-runner 插件帮助",
        )


def _handle_target(
    target: SweTarget,
    rest: str,
    catalog: SweRunnerCatalog,
    context: ActionContext,
) -> str:
    action = rest.strip().lower()
    if not action or action in HELP_COMMANDS:
        return _format_help(catalog)
    if action in STATUS_COMMANDS:
        return _run_status(target, False, catalog.settings, context)
    if action in HISTORY_COMMANDS:
        return _run_status(target, True, catalog.settings, context)
    raise SweRunnerError(f"swe-runner 目标 `{target.name}` 支持 `status` 或 `history`。")


def _load_catalog(context: ActionContext) -> SweRunnerCatalog:
    source = _config_path(context)
    if not source.exists():
        return SweRunnerCatalog(default=None)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SweRunnerError(f"cannot read swe-runner config {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise SweRunnerError("swe-runner config root must be an object")

    settings_raw = raw.get("settings", {})
    if not isinstance(settings_raw, dict):
        raise SweRunnerError("'settings' must be an object")
    settings = SweRunnerSettings(
        raw_lines=_positive_int(settings_raw.get("rawLines", 120), "settings.rawLines"),
        timeout_seconds=_positive_float(settings_raw.get("timeoutSeconds", 30), "settings.timeoutSeconds"),
        max_output_chars=_positive_int(
            settings_raw.get("maxOutputChars", 8000), "settings.maxOutputChars"
        ),
        max_reply_chars=_positive_int(
            settings_raw.get("maxReplyChars", 12000), "settings.maxReplyChars"
        ),
    )

    targets_raw = raw.get("targets", {})
    if not isinstance(targets_raw, dict):
        raise SweRunnerError("'targets' must be an object")
    targets: dict[str, SweTarget] = {}
    for name, item in targets_raw.items():
        if not isinstance(item, dict):
            raise SweRunnerError(f"target {name!r} must be an object")
        node_name = _optional_string(item.get("node"))
        host = str(item.get("host", "")).strip()
        queue = str(item.get("queue", "")).strip()
        user = str(item.get("user", "")).strip()
        if not queue:
            raise SweRunnerError(f"target {name!r} requires queue")
        if node_name:
            conflicting = sorted(
                set(item) & {"host", "user", "passwordEnv", "port", "strictHostKeyChecking"}
            )
            if conflicting:
                raise SweRunnerError(
                    f"target {name!r} uses node {node_name!r}; remove inline fields: "
                    f"{', '.join(conflicting)}"
                )
        elif not host or not user:
            raise SweRunnerError(
                f"target {name!r} requires either node or inline host and user"
            )
        aliases_raw = item.get("aliases", [])
        if not isinstance(aliases_raw, list):
            raise SweRunnerError(f"target {name!r} aliases must be an array")
        try:
            port = int(item.get("port", 22))
        except (TypeError, ValueError) as exc:
            raise SweRunnerError(f"target {name!r} port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise SweRunnerError(f"target {name!r} port must be between 1 and 65535")
        password_env = _optional_string(item.get("passwordEnv"))
        if password_env and ENV_NAME_RE.fullmatch(password_env) is None:
            raise SweRunnerError(f"target {name!r} passwordEnv must be a valid environment variable name")
        strict = str(item.get("strictHostKeyChecking", "accept-new")).lower()
        if strict not in STRICT_HOST_KEY_VALUES:
            raise SweRunnerError(
                f"target {name!r} strictHostKeyChecking must be one of: yes, no, accept-new"
            )
        targets[name] = SweTarget(
            name=name,
            queue=queue,
            node=node_name,
            host=host or None,
            user=user or None,
            password_env=password_env,
            remote_dir=str(item.get("remoteDir", DEFAULT_REMOTE_DIR)),
            aliases=tuple(str(alias) for alias in aliases_raw),
            port=port,
            strict_host_key_checking=strict,
        )

    default = _optional_string(raw.get("default"))
    if default and default not in targets:
        raise SweRunnerError(f"default target {default!r} is not registered")
    return SweRunnerCatalog(default=default, targets=targets, settings=settings)


def _config_path(context: ActionContext) -> Path:
    configured = os.getenv("SWE_RUNNER_CONFIG")
    if configured:
        return Path(configured).expanduser()
    config_dir = context.resources.get(RESOURCE_CONFIG_DIR)
    if config_dir:
        candidate = Path(str(config_dir)) / "swe-runner.json"
        if candidate.exists():
            return candidate
    return PLUGIN_ROOT / "config" / "swe-runner.json"


def _target_command(
    target: SweTarget,
    remote_command: str,
    context: ActionContext,
    *,
    materialize_password: bool,
) -> tuple[tuple[str, ...], dict[str, str], str]:
    if target.node:
        service = context.require_service(NODES_SERVICE)
        node_command = service.ssh_command(target.node, remote_command, context)
        env = dict(node_command.env)
        if materialize_password:
            env = _materialize_env(env)
        return tuple(node_command.argv), env, str(node_command.node.host)

    command, env = _ssh_command(target, remote_command)
    if target.password_env:
        password = os.getenv(target.password_env)
        if not password:
            raise SweRunnerError(
                f"target {target.name!r} password environment variable {target.password_env} is not set"
            )
        env = {"SSHPASS": password if materialize_password else f"${{{target.password_env}}}"}
    return command, env, str(target.host or "-")


def _materialize_env(env: Mapping[str, str]) -> dict[str, str]:
    materialized: dict[str, str] = {}
    for key, value in env.items():
        match = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", value)
        if match is None:
            materialized[key] = value
            continue
        resolved = os.getenv(match.group(1))
        if resolved is None:
            raise SweRunnerError(f"environment variable {match.group(1)} is not set")
        materialized[key] = resolved
    return materialized


def _run_status(
    target: SweTarget,
    history: bool,
    settings: SweRunnerSettings,
    context: ActionContext,
) -> str:
    command, env, host = _target_command(
        target,
        target.remote_command(history),
        context,
        materialize_password=True,
    )
    process = _run_process(
        command,
        timeout_seconds=settings.timeout_seconds,
        env=env,
        max_output_chars=settings.max_output_chars,
    )
    return _format_status(target, history, process, settings, host=host)


def _format_status(
    target: SweTarget,
    history: bool,
    process: _ProcessResult,
    settings: SweRunnerSettings,
    *,
    host: str | None = None,
) -> str:
    raw = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
    total = _first_match(raw, r"Total tasks:\s+([0-9]+)")
    running = _first_match(raw, r"Running:\s+([0-9]+)")
    completed = _first_match(raw, r"Completed:\s+([0-9]+\s+\(success=[0-9]+, failed=[0-9]+\))")
    progress = _first_match(raw, r"Progress:\s+([0-9.]+)%")
    success_rate = _first_match(raw, r"Success rate:\s+([0-9.]+)%")

    label = "history" if history else "status"
    lines = [
        f"### swe-runner {label} - {target.name}",
        "",
        f"- host: {host or target.host or target.node or '-'}",
        f"- queue: {target.queue}",
        f"- total: {total or '?'}",
        f"- running: {running or '?'}",
        f"- completed: {completed or '?'}",
        f"- progress: {progress or '?'}%",
        f"- success rate: {success_rate or '?'}%",
        f"- exit code: {process.exit_code}",
        f"- duration: {process.duration_ms}ms",
    ]
    if process.timed_out:
        lines.append("- error: command timed out")
    if raw:
        raw_lines = "\n".join(raw.splitlines()[: settings.raw_lines])
        lines.extend(["", _code_block(raw_lines, limit=settings.max_output_chars)])
    else:
        lines.extend(["", "(no output)"])
    return _truncate_text("\n".join(lines), settings.max_reply_chars)


def _format_help(catalog: SweRunnerCatalog) -> str:
    if not catalog.targets:
        return "\n".join(
            [
                "### swe-runner 插件",
                "",
            "尚未配置目标。请填写插件目录下的 `config/swe-runner.json`，或设置 `SWE_RUNNER_CONFIG`。",
            ]
        )
    targets = ", ".join(f"`{name}`" for name in sorted(catalog.targets))
    aliases = [f"`{name}`: {', '.join(target.aliases)}" for name, target in sorted(catalog.targets.items()) if target.aliases]
    locations = [
        f"`{name}`: {target.node or target.host or '-'}"
        for name, target in sorted(catalog.targets.items())
    ]
    return "\n".join(
        [
            "### swe-runner 插件",
            "",
            f"- 默认目标：`{catalog.default or '-'}`",
            f"- 已配置目标：{targets}",
            f"- 节点/主机：{', '.join(locations)}",
            "- `status`：默认目标实时状态",
            "- `history`：默认目标历史状态",
            "- `<目标> status`：指定目标实时状态",
            "- `<别名> history`：通过别名查询历史状态",
            "- `swe-runner check`：旧语义兼容",
            "",
            "别名：" if aliases else "别名：-",
            *aliases,
        ]
    )


def _format_swe_help(catalog: SweRunnerCatalog) -> str:
    targets = ", ".join(f"`{name}`" for name in sorted(catalog.targets)) or "-"
    return "\n".join(
        [
            "### swe-runner 插件",
            "",
            "- `swe-runner status`：查询默认目标实时状态",
            "- `swe-runner history`：查询默认目标历史状态",
            "- `swe-runner <目标> status|history`：查询指定目标",
            "- `<目标> status|history`：兼容旧 bridge 的写法",
            "- `swe-runner help [目标]`：查看插件或目标帮助",
            "",
            f"- 默认目标：`{catalog.default or '-'}`",
            f"- 已配置目标：{targets}",
        ]
    )


def _format_target_help(target: SweTarget) -> str:
    aliases = ", ".join(f"`{alias}`" for alias in target.aliases) or "-"
    location = target.node or target.host or "-"
    return "\n".join(
        [
            f"### swe-runner 目标：{target.name}",
            "",
            f"- 节点/主机：`{location}`",
            f"- 队列：`{target.queue}`",
            f"- 别名：{aliases}",
            "",
            f"示例：`swe-runner {target.name} status`、`swe-runner {target.name} history`。",
        ]
    )


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int


def _ssh_command(target: SweTarget, remote_command: str) -> tuple[tuple[str, ...], dict[str, str]]:
    if not target.host or not target.user:
        raise SweRunnerError(f"target {target.name!r} has no inline host/user")
    known_hosts = os.getenv("SWE_RUNNER_KNOWN_HOSTS", str(_data_dir() / "known_hosts"))
    args: list[str] = [
        "ssh",
        "-p",
        str(target.port),
        "-o",
        "ConnectTimeout=15",
        "-o",
        f"StrictHostKeyChecking={target.strict_host_key_checking}",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "LogLevel=ERROR",
    ]
    if not target.password_env:
        args.extend(["-o", "BatchMode=yes"])
    args.extend([f"{target.user}@{target.host}", remote_command])
    if target.password_env:
        return ("sshpass", "-e", *args), {}
    return tuple(args), {}


def _data_dir() -> Path:
    configured = os.getenv("DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    container_dir = Path("/app/data")
    if container_dir.is_dir():
        return container_dir
    return PLUGIN_ROOT / "data"


def _run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
    max_output_chars: int,
) -> _ProcessResult:
    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(key): str(value) for key, value in env.items()})
    started = time.monotonic()
    with tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b") as stdout_file:
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b") as stderr_file:
            try:
                process = subprocess.Popen(
                    [str(part) for part in argv],
                    env=merged_env,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                )
            except OSError as exc:
                return _ProcessResult(127, "", str(exc), False, int((time.monotonic() - started) * 1000))
            timed_out = False
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(process.pid)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            elapsed = int((time.monotonic() - started) * 1000)
            return _ProcessResult(
                exit_code=process.returncode if process.returncode is not None else -1,
                stdout=_read_output(stdout_file, max_output_chars),
                stderr=_read_output(stderr_file, max_output_chars),
                timed_out=timed_out,
                duration_ms=elapsed,
            )


def _kill_process_group(pid: int) -> None:
    try:
        if hasattr(os, "killpg"):
            os.killpg(pid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _read_output(handle: object, limit: int) -> str:
    if not hasattr(handle, "seek") or not hasattr(handle, "read"):
        return ""
    handle.seek(0)
    data = handle.read(max(4096, limit * 4 + 16))
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    return _truncate_text(text, limit)


def _first_match(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _as_bool(value: Any, label: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise SweRunnerError(f"{label} must be a boolean")


def _positive_int(value: Any, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise SweRunnerError(f"{label} must be an integer") from exc
    if parsed <= 0:
        raise SweRunnerError(f"{label} must be greater than zero")
    return parsed


def _positive_float(value: Any, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise SweRunnerError(f"{label} must be a number") from exc
    if parsed <= 0:
        raise SweRunnerError(f"{label} must be greater than zero")
    return parsed


def _truncate_text(text: str, limit: int, suffix: str = "\n... [truncated]") -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    if len(suffix) >= limit:
        return text[:limit]
    return text[: limit - len(suffix)] + suffix


def _code_block(text: str, limit: int = 3600) -> str:
    content = _truncate_text(text.rstrip(), limit)
    if not content:
        return "(no output)"
    escaped = content.replace("```", "'''")
    return f"```text\n{escaped}\n```"


PROVIDER = SweRunnerActionProvider()
COMMAND_PROVIDER = SweRunnerCommandProvider()
