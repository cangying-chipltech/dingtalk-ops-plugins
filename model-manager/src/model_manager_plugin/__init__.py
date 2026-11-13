from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from dingtalk_ops_bridge.plugin_api import (
    PLUGIN_API_VERSION,
    ActionContext,
    ActionValidationError,
    MonitorResult,
)


PLUGIN_ROOT = Path(__file__).resolve().parents[2]
NODES_SERVICE = "nodes"
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MONITOR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ENV_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
SEVERITIES = {"info", "warning", "critical"}
MAX_DETAILS_CHARS = 4000


class ModelManagerError(ActionValidationError):
    """Raised when model configuration or execution is invalid."""


@dataclass(frozen=True)
class ModelDefinition:
    name: str
    node: str
    log_path: str
    alert_patterns: tuple[str, ...]
    description: str = ""
    monitor_name: str = ""
    tail_lines: int = 10
    interval_seconds: float = 60.0
    timeout_seconds: float = 20.0
    severity: str = "critical"
    repeat_alert_seconds: float = 0.0
    notify_recovery: bool = True
    enabled: bool = True

    @property
    def effective_monitor_name(self) -> str:
        return self.monitor_name or f"model-manager-{self.name}-log"


@dataclass(frozen=True)
class ServiceDefinition:
    name: str
    node: str
    description: str = ""
    monitor_name: str = ""
    container: str = ""
    url: str = ""
    expected_status: int = 200
    url_timeout_seconds: float = 5.0
    interval_seconds: float = 60.0
    timeout_seconds: float = 20.0
    severity: str = "critical"
    repeat_alert_seconds: float = 0.0
    notify_recovery: bool = True
    enabled: bool = True

    @property
    def effective_monitor_name(self) -> str:
        return self.monitor_name or f"model-manager-{self.name}-service"


@dataclass(frozen=True)
class ModelCatalog:
    models: Mapping[str, ModelDefinition] = field(default_factory=dict)
    services: Mapping[str, ServiceDefinition] = field(default_factory=dict)

    def resolve(self, name: str) -> ModelDefinition | None:
        wanted = str(name).strip().casefold()
        for model_name, model in self.models.items():
            if model_name.casefold() == wanted:
                return model
        return None

    def resolve_service(self, name: str) -> ServiceDefinition | None:
        wanted = str(name).strip().casefold()
        for service_name, service in self.services.items():
            if service_name.casefold() == wanted:
                return service
        return None


class ModelService:
    api_version = PLUGIN_API_VERSION

    def list_models(self, context: ActionContext) -> tuple[ModelDefinition, ...]:
        return tuple(_load_catalog(context).models.values())

    def resolve(self, name: str, context: ActionContext) -> ModelDefinition | None:
        return _load_catalog(context).resolve(name)


class ModelMonitorProvider:
    api_version = PLUGIN_API_VERSION
    type_name = "model-log"

    def monitors(self, context: ActionContext) -> Mapping[str, Mapping[str, Any]]:
        catalog = _load_catalog(context)
        nodes = context.require_service(NODES_SERVICE)
        monitors: dict[str, Mapping[str, Any]] = {}
        for model in catalog.models.values():
            if nodes.resolve(model.node, context) is None:
                raise ModelManagerError(
                    f"model {model.name!r} references unknown node {model.node!r}"
                )
            monitors[model.effective_monitor_name] = {
                "description": model.description
                or f"{model.name} vLLM 日志异常检查（{model.node}）",
                "check": {"type": self.type_name, "model": model.name},
                "intervalSeconds": model.interval_seconds,
                "timeoutSeconds": model.timeout_seconds,
                "severity": model.severity,
                "repeatAlertSeconds": model.repeat_alert_seconds,
                "notifyRecovery": model.notify_recovery,
                "enabled": model.enabled,
            }
        return monitors

    def validate(self, check: Mapping[str, Any]) -> None:
        if not _optional_string(check.get("model")):
            raise ModelManagerError("model-log check requires 'model'")

    def check(self, check: Mapping[str, Any], context: ActionContext) -> MonitorResult:
        model_name = _optional_string(check.get("model"))
        if not model_name:
            return MonitorResult(False, "model-log check requires 'model'")
        model = _load_catalog(context).resolve(model_name)
        if model is None:
            return MonitorResult(False, f"unknown model: {model_name}")

        nodes = context.require_service(NODES_SERVICE)
        ssh = nodes.ssh_command(model.node, _remote_log_command(model), context)
        env = _materialize_env(ssh.env)
        process = _run_process(
            ssh.argv,
            timeout_seconds=model.timeout_seconds,
            env=env,
            max_output_chars=MAX_DETAILS_CHARS,
        )
        location = f"model={model.name} node={model.node} log={model.log_path}"
        if process.timed_out:
            return MonitorResult(
                False,
                f"日志检查超时（{model.timeout_seconds:g}s）",
                location,
            )
        if process.exit_code == 0:
            return MonitorResult(
                True,
                f"最近 {model.tail_lines} 行日志未命中异常关键字",
                location,
            )
        details = _truncate_text(
            (process.stderr or process.stdout).strip(),
            MAX_DETAILS_CHARS,
        )
        if process.exit_code == 1:
            return MonitorResult(False, "vLLM 日志命中异常关键字", details or location)
        if process.exit_code == 2:
            return MonitorResult(False, "无法读取 vLLM 日志", details or location)
        message = process.error or f"SSH 日志检查失败，退出码 {process.exit_code}"
        return MonitorResult(False, message, details or location)


class ServiceMonitorProvider:
    api_version = PLUGIN_API_VERSION
    type_name = "node-service"

    def monitors(self, context: ActionContext) -> Mapping[str, Mapping[str, Any]]:
        catalog = _load_catalog(context)
        nodes = context.require_service(NODES_SERVICE)
        monitors: dict[str, Mapping[str, Any]] = {}
        for service in catalog.services.values():
            if nodes.resolve(service.node, context) is None:
                raise ModelManagerError(
                    f"service {service.name!r} references unknown node {service.node!r}"
                )
            monitors[service.effective_monitor_name] = {
                "description": service.description
                or f"{service.name} 服务健康检查（{service.node}）",
                "check": {"type": self.type_name, "service": service.name},
                "intervalSeconds": service.interval_seconds,
                "timeoutSeconds": service.timeout_seconds,
                "severity": service.severity,
                "repeatAlertSeconds": service.repeat_alert_seconds,
                "notifyRecovery": service.notify_recovery,
                "enabled": service.enabled,
            }
        return monitors

    def validate(self, check: Mapping[str, Any]) -> None:
        if not _optional_string(check.get("service")):
            raise ModelManagerError("node-service check requires 'service'")

    def check(self, check: Mapping[str, Any], context: ActionContext) -> MonitorResult:
        service_name = _optional_string(check.get("service"))
        if not service_name:
            return MonitorResult(False, "node-service check requires 'service'")
        service = _load_catalog(context).resolve_service(service_name)
        if service is None:
            return MonitorResult(False, f"unknown service: {service_name}")

        nodes = context.require_service(NODES_SERVICE)
        ssh = nodes.ssh_command(service.node, _remote_service_command(service), context)
        env = _materialize_env(ssh.env)
        process = _run_process(
            ssh.argv,
            timeout_seconds=service.timeout_seconds,
            env=env,
            max_output_chars=MAX_DETAILS_CHARS,
        )
        location = _service_location(service)
        if process.timed_out:
            return MonitorResult(
                False,
                f"服务检查超时（{service.timeout_seconds:g}s）",
                location,
            )
        if process.exit_code == 0:
            return MonitorResult(True, "服务状态正常", location)

        details = _truncate_text(
            (process.stderr or process.stdout).strip(),
            MAX_DETAILS_CHARS,
        )
        if process.exit_code == 3:
            return MonitorResult(False, "服务容器未运行", details or location)
        if process.exit_code == 4:
            return MonitorResult(False, "服务健康检查请求失败", details or location)
        if process.exit_code == 5:
            return MonitorResult(
                False,
                f"服务 HTTP 状态异常（期望 {service.expected_status}）",
                details or location,
            )
        message = process.error or f"SSH 服务检查失败，退出码 {process.exit_code}"
        return MonitorResult(False, message, details or location)


class ModelManagerCommandProvider:
    api_version = PLUGIN_API_VERSION
    command_prefixes = ("model", "models", "模型")

    def handle(self, prompt: str, context: ActionContext) -> str | None:
        text = (prompt or "").strip()
        parts = text.split(maxsplit=1)
        if not parts:
            return None
        command = parts[0].casefold()
        if command not in self.command_prefixes:
            return None
        rest = parts[1].strip() if len(parts) > 1 else ""
        if not rest:
            return _format_help(_load_catalog(context))

        subcommand, _, argument = rest.partition(" ")
        subcommand = subcommand.casefold()
        if subcommand in {"list", "ls", "列表"}:
            return _format_model_list(_load_catalog(context))
        if subcommand in {"check", "status", "monitor", "检查", "状态"}:
            return self._check(argument.strip(), context)
        if subcommand in {"help", "?", "/help", "帮助"}:
            return _format_help(_load_catalog(context))
        return _format_help(_load_catalog(context))

    def _check(self, argument: str, context: ActionContext) -> str:
        catalog = _load_catalog(context)
        names = [item for item in re.split(r"[,\s]+", argument) if item]
        if names:
            models = []
            for name in names:
                model = catalog.resolve(name)
                if model is None:
                    return f"### 模型检查\n\n- 未知模型：`{name}`"
                models.append(model)
        else:
            models = list(catalog.models.values())
        if not models:
            return _format_help(catalog)
        results = [(model, MONITOR_PROVIDER.check({"model": model.name}, context)) for model in models]
        return _format_checks(results)

    def help_lines(self) -> list[str]:
        return [
            "- `model list`：列出模型实例和监控配置",
            "- `model check [名称,...]`：立即检查模型日志",
        ]


def _load_catalog(context: ActionContext | None = None) -> ModelCatalog:
    source = _config_file()
    if not source.is_file():
        return ModelCatalog()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelManagerError(f"cannot read model config {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ModelManagerError(f"model config {source} must be an object")
    models_raw = raw.get("models", {})
    if not isinstance(models_raw, dict):
        raise ModelManagerError("'models' must be an object")
    models: dict[str, ModelDefinition] = {}
    for name, item in models_raw.items():
        if not isinstance(item, dict):
            raise ModelManagerError(f"model {name!r} must be an object")
        models[name] = _parse_model(name, item)
    services_raw = raw.get("services", {})
    if not isinstance(services_raw, dict):
        raise ModelManagerError("'services' must be an object")
    services: dict[str, ServiceDefinition] = {}
    for name, item in services_raw.items():
        if not isinstance(item, dict):
            raise ModelManagerError(f"service {name!r} must be an object")
        services[name] = _parse_service(name, item)
    return ModelCatalog(models=models, services=services)


def _parse_model(name: str, item: Mapping[str, Any]) -> ModelDefinition:
    if MODEL_NAME_RE.fullmatch(name) is None:
        raise ModelManagerError(
            f"invalid model name {name!r}; use letters, digits, dot, underscore or dash"
        )
    node = _optional_string(item.get("node"))
    log_path = _optional_string(item.get("logPath"))
    if not node:
        raise ModelManagerError(f"model {name!r} requires 'node'")
    if not log_path or not Path(log_path).is_absolute():
        raise ModelManagerError(f"model {name!r} requires an absolute 'logPath'")
    patterns_raw = item.get("alertPatterns", [])
    if isinstance(patterns_raw, str):
        patterns_raw = [patterns_raw]
    if not isinstance(patterns_raw, list):
        raise ModelManagerError(f"model {name!r} alertPatterns must be an array")
    patterns: list[str] = []
    for value in patterns_raw:
        pattern = str(value).strip()
        if not pattern:
            raise ModelManagerError(f"model {name!r} alertPatterns must not be empty")
        if pattern not in patterns:
            patterns.append(pattern)
    if not patterns:
        raise ModelManagerError(f"model {name!r} requires at least one alert pattern")

    monitor_name = _optional_string(item.get("monitorName")) or f"model-manager-{name}-log"
    if MONITOR_NAME_RE.fullmatch(monitor_name) is None:
        raise ModelManagerError(f"model {name!r} has invalid monitorName {monitor_name!r}")
    severity = str(item.get("severity", "critical")).strip().lower()
    if severity not in SEVERITIES:
        raise ModelManagerError(f"model {name!r} severity must be info, warning, or critical")
    return ModelDefinition(
        name=name,
        node=node,
        log_path=log_path,
        alert_patterns=tuple(patterns),
        description=str(item.get("description", "")),
        monitor_name=monitor_name,
        tail_lines=_bounded_int(item.get("tailLines", 10), f"model {name}.tailLines", 1, 1000),
        interval_seconds=_positive_float(
            item.get("intervalSeconds", 60),
            f"model {name}.intervalSeconds",
        ),
        timeout_seconds=_positive_float(
            item.get("timeoutSeconds", 20),
            f"model {name}.timeoutSeconds",
        ),
        severity=severity,
        repeat_alert_seconds=_non_negative_float(
            item.get("repeatAlertSeconds", 0),
            f"model {name}.repeatAlertSeconds",
        ),
        notify_recovery=_as_bool(
            item.get("notifyRecovery", True),
            f"model {name}.notifyRecovery",
        ),
        enabled=_as_bool(item.get("enabled", True), f"model {name}.enabled"),
    )


def _parse_service(name: str, item: Mapping[str, Any]) -> ServiceDefinition:
    if MODEL_NAME_RE.fullmatch(name) is None:
        raise ModelManagerError(
            f"invalid service name {name!r}; use letters, digits, dot, underscore or dash"
        )
    node = _optional_string(item.get("node"))
    container = _optional_string(item.get("container")) or ""
    url = _optional_string(item.get("url")) or ""
    if not node:
        raise ModelManagerError(f"service {name!r} requires 'node'")
    if not container and not url:
        raise ModelManagerError(f"service {name!r} requires 'container' or 'url'")
    if url:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ModelManagerError(
                f"service {name!r} requires an absolute HTTP(S) 'url'"
            )

    monitor_name = _optional_string(item.get("monitorName")) or f"model-manager-{name}-service"
    if MONITOR_NAME_RE.fullmatch(monitor_name) is None:
        raise ModelManagerError(f"service {name!r} has invalid monitorName {monitor_name!r}")
    severity = str(item.get("severity", "critical")).strip().lower()
    if severity not in SEVERITIES:
        raise ModelManagerError(f"service {name!r} severity must be info, warning, or critical")
    return ServiceDefinition(
        name=name,
        node=node,
        description=str(item.get("description", "")),
        monitor_name=monitor_name,
        container=container,
        url=url,
        expected_status=_bounded_int(
            item.get("expectedStatus", 200),
            f"service {name}.expectedStatus",
            100,
            599,
        ),
        url_timeout_seconds=_positive_float(
            item.get("urlTimeoutSeconds", 5),
            f"service {name}.urlTimeoutSeconds",
        ),
        interval_seconds=_positive_float(
            item.get("intervalSeconds", 60),
            f"service {name}.intervalSeconds",
        ),
        timeout_seconds=_positive_float(
            item.get("timeoutSeconds", 20),
            f"service {name}.timeoutSeconds",
        ),
        severity=severity,
        repeat_alert_seconds=_non_negative_float(
            item.get("repeatAlertSeconds", 0),
            f"service {name}.repeatAlertSeconds",
        ),
        notify_recovery=_as_bool(
            item.get("notifyRecovery", True),
            f"service {name}.notifyRecovery",
        ),
        enabled=_as_bool(item.get("enabled", True), f"service {name}.enabled"),
    )


def _config_file() -> Path:
    configured = os.getenv("MODEL_MANAGER_CONFIG")
    if configured:
        return Path(configured).expanduser().resolve()
    return PLUGIN_ROOT / "config" / "models.json"


def _remote_log_command(model: ModelDefinition) -> str:
    path = shlex.quote(model.log_path)
    grep_args = " ".join(f"-e {shlex.quote(pattern)}" for pattern in model.alert_patterns)
    read_error = shlex.quote(f"cannot read {model.log_path}")
    return (
        f"if [ ! -r {path} ]; then echo {read_error} >&2; exit 2; fi; "
        f"last=$(tail -n {model.tail_lines} -- {path}) || "
        f"{{ echo {read_error} >&2; exit 2; }}; "
        f"if printf '%s\\n' \"$last\" | grep -Fq {grep_args}; then "
        f"printf '%s\\n' \"$last\" | grep -F {grep_args} >&2; exit 1; fi; "
        "exit 0"
    )


def _remote_service_command(service: ServiceDefinition) -> str:
    container_check = ""
    if service.container:
        container = shlex.quote(service.container)
        container_error = shlex.quote(f"container not running: {service.container}")
        container_check = (
            "if ! command -v docker >/dev/null 2>&1; then "
            "echo 'docker command not found' >&2; exit 4; fi; "
            f"running=$(docker inspect -f '{{{{.State.Running}}}}' {container} "
            "2>/dev/null || true); "
            f"if [ \"$running\" != true ]; then echo {container_error} >&2; exit 3; fi; "
        )

    http_check = ""
    if service.url:
        url = shlex.quote(service.url)
        request_error = shlex.quote(f"request failed: {service.url}")
        http_check = (
            "if ! command -v curl >/dev/null 2>&1; then "
            "echo 'curl command not found' >&2; exit 4; fi; "
            f"code=$(curl -sS --max-time {service.url_timeout_seconds:g} "
            f"-o /dev/null -w '%{{http_code}}' {url}) || "
            f"{{ echo {request_error} >&2; exit 4; }}; "
            f"if [ \"$code\" != {shlex.quote(str(service.expected_status))} ]; then "
            f"echo \"unexpected HTTP status: $code\" >&2; exit 5; fi; "
        )
    return container_check + http_check + "exit 0"


def _service_location(service: ServiceDefinition) -> str:
    parts = [f"service={service.name}", f"node={service.node}"]
    if service.container:
        parts.append(f"container={service.container}")
    if service.url:
        parts.append(f"url={service.url}")
    return " ".join(parts)


@dataclass(frozen=True)
class _ProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_ms: int
    error: str = ""


def _run_process(
    argv: Sequence[str],
    *,
    timeout_seconds: float,
    env: Mapping[str, str],
    max_output_chars: int,
) -> _ProcessResult:
    merged_env = os.environ.copy()
    merged_env.update({str(key): str(value) for key, value in env.items()})
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [str(part) for part in argv],
            env=merged_env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
        return _ProcessResult(
            -1,
            _truncate_text(stdout, max_output_chars),
            _truncate_text(stderr, max_output_chars),
            True,
            int((time.monotonic() - started) * 1000),
        )
    except OSError as exc:
        return _ProcessResult(
            127,
            "",
            "",
            False,
            int((time.monotonic() - started) * 1000),
            str(exc),
        )
    return _ProcessResult(
        completed.returncode,
        _truncate_text(completed.stdout, max_output_chars),
        _truncate_text(completed.stderr, max_output_chars),
        False,
        int((time.monotonic() - started) * 1000),
    )


def _materialize_env(env: Mapping[str, str]) -> dict[str, str]:
    materialized: dict[str, str] = {}
    for key, value in env.items():
        match = ENV_PLACEHOLDER_RE.fullmatch(value)
        if match is None:
            materialized[key] = value
            continue
        resolved = os.getenv(match.group(1))
        if resolved is None:
            raise ModelManagerError(f"environment variable {match.group(1)} is not set")
        materialized[key] = resolved
    return materialized


def _format_model_list(catalog: ModelCatalog) -> str:
    if not catalog.models:
        return _format_help(catalog)
    lines = [
        "### 模型清单",
        "",
        "| 模型 | 节点 | 日志 | 关键字 | 监控项 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for model in sorted(catalog.models.values(), key=lambda item: item.name):
        patterns = ", ".join(f"`{pattern}`" for pattern in model.alert_patterns)
        lines.append(
            f"| `{model.name}` | `{model.node}` | `{model.log_path}` | "
            f"{patterns} | `{model.effective_monitor_name}` |"
        )
    if catalog.services:
        lines.extend(
            [
                "",
                "### 服务监控",
                "",
                "| 服务 | 节点 | 容器 | URL | 监控项 |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for service in sorted(catalog.services.values(), key=lambda item: item.name):
            lines.append(
                f"| `{service.name}` | `{service.node}` | "
                f"{_inline_code(service.container)} | {_inline_code(service.url)} | "
                f"`{service.effective_monitor_name}` |"
            )
    lines.extend(["", "使用示例：`model check vllm-27`。"])
    return "\n".join(lines)


def _format_checks(results: Sequence[tuple[ModelDefinition, MonitorResult]]) -> str:
    failed = sum(1 for _, result in results if not result.ok)
    lines = [
        "### 模型日志检查",
        "",
        f"- 总数：**{len(results)}**",
        f"- 正常：**{len(results) - failed}**",
        f"- 异常：**{failed}**",
    ]
    for model, result in results:
        icon = "✅" if result.ok else "❌"
        lines.extend(
            [
                "",
                f"#### {icon} {model.name}",
                "",
                f"- 节点：`{model.node}`",
                f"- 日志：`{model.log_path}`",
                f"- 结果：{result.message}",
            ]
        )
        if result.details and result.details != f"model={model.name} node={model.node} log={model.log_path}":
            lines.extend(["", f"```text\n{_truncate_text(result.details, MAX_DETAILS_CHARS)}\n```"])
    return "\n".join(lines)


def _format_help(catalog: ModelCatalog) -> str:
    if not catalog.models:
        return "\n".join(
            [
                "### 模型管理插件",
                "",
                "尚未配置模型。请填写插件目录下的 `config/models.json`，或设置 `MODEL_MANAGER_CONFIG`。",
            ]
        )
    names = ", ".join(f"`{name}`" for name in sorted(catalog.models))
    return "\n".join(
        [
            "### 模型管理插件",
            "",
            f"- 已配置模型：{names}",
            "- `model list`：列出模型和监控项",
            "- `model check [名称,...]`：立即检查模型日志",
            "",
            "模型日志和服务健康异常会由插件声明的监控项上报钉钉 Webhook。",
        ]
    )


def _inline_code(value: str) -> str:
    return f"`{value}`" if value else "-"


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
    raise ModelManagerError(f"{label} must be a boolean")


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ModelManagerError(f"{label} must be an integer") from exc
    if not minimum <= parsed <= maximum:
        raise ModelManagerError(f"{label} must be between {minimum} and {maximum}")
    return parsed


def _positive_float(value: Any, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ModelManagerError(f"{label} must be a number") from exc
    if parsed <= 0:
        raise ModelManagerError(f"{label} must be greater than zero")
    return parsed


def _non_negative_float(value: Any, label: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ModelManagerError(f"{label} must be a number") from exc
    if parsed < 0:
        raise ModelManagerError(f"{label} must not be negative")
    return parsed


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)


def _truncate_text(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    suffix = "\n... [truncated]"
    return text[: max(0, limit - len(suffix))] + suffix


SERVICE = ModelService()
COMMAND_PROVIDER = ModelManagerCommandProvider()
MONITOR_PROVIDER = ModelMonitorProvider()
SERVICE_MONITOR_PROVIDER = ServiceMonitorProvider()
