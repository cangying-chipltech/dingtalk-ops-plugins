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
    ActionError,
    ActionValidationError,
    MonitorResult,
)

from .alerts import (
    AlertManagementError,
    apply_management,
    clean_names,
    load_management,
    save_management,
)
from .model_state import ModelStateError, load_models, save_models, state_file


PLUGIN_ROOT = Path(__file__).resolve().parents[2]
NODES_SERVICE = "nodes"
MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MONITOR_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ENV_PLACEHOLDER_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
SEVERITIES = {"info", "warning", "critical"}
MODEL_COMMANDS = {"model", "models", "模型"}
ALERT_COMMANDS = {"alert", "alerts", "告警"}
ALERT_TYPES = {"model-log", "node-service", "http", "tcp", "command"}
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


def _model_monitors(context: ActionContext) -> dict[str, Mapping[str, Any]]:
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
            "check": {"type": "model-log", "model": model.name},
            "intervalSeconds": model.interval_seconds,
            "timeoutSeconds": model.timeout_seconds,
            "severity": model.severity,
            "repeatAlertSeconds": model.repeat_alert_seconds,
            "notifyRecovery": model.notify_recovery,
            "enabled": model.enabled,
        }
    return monitors


def _service_monitors(context: ActionContext) -> dict[str, Mapping[str, Any]]:
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
            "check": {"type": "node-service", "service": service.name},
            "intervalSeconds": service.interval_seconds,
            "timeoutSeconds": service.timeout_seconds,
            "severity": service.severity,
            "repeatAlertSeconds": service.repeat_alert_seconds,
            "notifyRecovery": service.notify_recovery,
            "enabled": service.enabled,
        }
    return monitors


class ModelMonitorProvider:
    api_version = PLUGIN_API_VERSION
    type_name = "model-log"

    def monitors(self, context: ActionContext) -> Mapping[str, Mapping[str, Any]]:
        return apply_management(
            _model_monitors(context),
            load_management(),
            exclude_type="node-service",
        )

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
        return apply_management(
            _service_monitors(context),
            load_management(),
            monitor_type="node-service",
        )

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
    command_prefixes = tuple(sorted(MODEL_COMMANDS | ALERT_COMMANDS))

    def handle(self, prompt: str, context: ActionContext) -> str | None:
        text = (prompt or "").strip()
        parts = text.split(maxsplit=1)
        if not parts:
            return None
        command = parts[0].casefold()
        if command not in self.command_prefixes:
            return None
        rest = parts[1].strip() if len(parts) > 1 else ""
        if command in ALERT_COMMANDS:
            return self._alert(rest, context)
        if not rest:
            return _format_help(_load_catalog(context))

        subcommand, _, argument = rest.partition(" ")
        subcommand = subcommand.casefold()
        if subcommand in ALERT_COMMANDS:
            return self._alert(argument.strip(), context)
        if subcommand in {"add", "create", "添加", "新增"}:
            try:
                definition = _add_model(
                    _parse_model_parameters(shlex.split(argument)), context
                )
                return _format_model_added(definition)
            except (
                ActionError,
                AlertManagementError,
                ModelManagerError,
                ModelStateError,
                ValueError,
            ) as exc:
                return _format_model_error(str(exc))
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

    def _alert(self, argument: str, context: ActionContext) -> str:
        try:
            tokens = shlex.split(argument)
            if not tokens:
                return _format_alert_list(context)
            subcommand = tokens[0].casefold()
            if subcommand in {"list", "ls", "状态", "列表"}:
                return _format_alert_list(context)
            if subcommand in {"disable", "off", "关闭", "停用"}:
                return _manage_alerts("关闭", tokens[1:], context)
            if subcommand in {"enable", "on", "启用", "开启"}:
                return _manage_alerts("启用", tokens[1:], context)
            if subcommand in {"remove", "delete", "rm", "移出", "移除", "删除"}:
                return _manage_alerts("移出", tokens[1:], context)
            if subcommand in {"restore", "恢复"}:
                return _manage_alerts("恢复", tokens[1:], context)
            if subcommand in {"add", "create", "添加", "新增"}:
                name, definition = _add_alert(
                    _parse_alert_parameters(tokens[1:]), context
                )
                return _format_alert_change("添加", (name,), definition)
            if subcommand in {"help", "?", "/help", "帮助", "describe", "详情", "说明"}:
                detail = tokens[1].casefold() if len(tokens) > 1 else None
                return _format_alert_help(detail)
            raise ModelManagerError(
                "alert 支持 `list`、`disable`、`enable`、`remove`、`restore` 或 `add`"
            )
        except (AlertManagementError, ModelManagerError, ValueError) as exc:
            return _format_alert_error(str(exc))

    def help_lines(self) -> list[str]:
        return [
            "- `model list`：列出模型实例和监控配置",
            "- `model check [名称,...]`：立即检查模型日志",
            "- `model add name=<名称> node=<节点> logPath=<路径> alertPatterns=<关键字> [参数...]`：添加模型",
            "- `alert list`：查看模型插件告警项状态",
            "- `alert disable|enable|remove|restore <名称,...>`：管理告警项",
            "- `alert add name=<名称> type=<类型> [参数...]`：添加告警项",
        ]


def _all_alerts(context: ActionContext) -> dict[str, Mapping[str, Any]]:
    monitors: dict[str, Mapping[str, Any]] = {}
    monitors.update(_model_monitors(context))
    monitors.update(_service_monitors(context))
    state = load_management()
    for name, item in state["added"].items():
        if name in monitors and name not in state["removed"]:
            raise AlertManagementError(
                f"managed alert {name!r} conflicts with an existing monitor"
            )
        monitors[name] = item
    return monitors


def _manage_alerts(action: str, tokens: Sequence[str], context: ActionContext) -> str:
    names = clean_names(tokens)
    if not names:
        raise ModelManagerError("please provide at least one alert name")

    state = load_management()
    known = _all_alerts(context)
    unknown = [name for name in names if name not in known]
    if unknown:
        raise ModelManagerError(f"unknown alert: {', '.join(unknown)}")

    removed = set(state["removed"])
    disabled = set(state["disabled"])
    if action in {"关闭", "启用"}:
        blocked = [name for name in names if name in removed]
        if blocked:
            raise ModelManagerError(
                f"alert is removed; restore it first: {', '.join(blocked)}"
            )
    if action == "移出":
        removed.update(names)
        disabled.difference_update(names)
    elif action == "恢复":
        missing = [name for name in names if name not in removed]
        if missing:
            raise ModelManagerError(f"alert is not removed: {', '.join(missing)}")
        removed.difference_update(names)
        disabled.difference_update(names)
    elif action == "关闭":
        disabled.update(names)
    elif action == "启用":
        disabled.difference_update(names)
    else:  # pragma: no cover - defensive
        raise ModelManagerError(f"unsupported alert operation: {action}")

    state["removed"] = sorted(removed)
    state["disabled"] = sorted(disabled)
    save_management(None, state)
    return _format_alert_change(action, names)


def _add_alert(
    parameters: Mapping[str, str],
    context: ActionContext,
) -> tuple[str, dict[str, Any]]:
    values = dict(parameters)
    name = str(values.pop("name", "")).strip()
    check_type = str(values.pop("type", "")).strip().lower()
    if not name:
        raise ModelManagerError("alert add requires name=<名称>")
    if MONITOR_NAME_RE.fullmatch(name) is None:
        raise ModelManagerError(
            "alert name must use letters, digits, dot, underscore, dash or colon"
        )
    if not check_type:
        if "model" in values:
            check_type = "model-log"
        elif "service" in values:
            check_type = "node-service"
        else:
            raise ModelManagerError("alert add requires type=<检查类型>")
    if check_type not in ALERT_TYPES:
        raise ModelManagerError(
            f"alert type must be one of: {', '.join(sorted(ALERT_TYPES))}"
        )

    state = load_management()
    known = _all_alerts(context)
    if name in known:
        if name in state["removed"] and name not in state["added"]:
            raise ModelManagerError(
                f"alert exists but is removed; restore it first: {name}"
            )
        if name not in state["removed"]:
            raise ModelManagerError(f"alert already exists: {name}")

    definition = _build_alert_definition(name, check_type, values, context)
    state["added"][name] = definition
    state["removed"] = [item for item in state["removed"] if item != name]
    disabled = set(state["disabled"])
    if bool(definition.get("enabled", True)):
        disabled.discard(name)
    else:
        disabled.add(name)
    state["disabled"] = sorted(disabled)
    save_management(None, state)
    return name, definition


def _build_alert_definition(
    name: str,
    check_type: str,
    values: Mapping[str, str],
    context: ActionContext,
) -> dict[str, Any]:
    params = dict(values)
    if check_type == "model-log":
        model_name = _optional_string(params.pop("model", None))
        if not model_name:
            raise ModelManagerError("model-log alert requires model=<模型名称>")
        model = _load_catalog(context).resolve(model_name)
        if model is None:
            raise ModelManagerError(f"unknown model: {model_name}")
        source = _model_monitors(context).get(model.effective_monitor_name)
        if source is None:  # pragma: no cover - guarded by catalog lookup
            raise ModelManagerError(f"cannot build alert from model: {model_name}")
        raw = dict(source)
    elif check_type == "node-service":
        service_name = _optional_string(params.pop("service", None))
        if not service_name:
            raise ModelManagerError("node-service alert requires service=<服务名称>")
        service = _load_catalog(context).resolve_service(service_name)
        if service is None:
            raise ModelManagerError(f"unknown service: {service_name}")
        source = _service_monitors(context).get(service.effective_monitor_name)
        if source is None:  # pragma: no cover - guarded by catalog lookup
            raise ModelManagerError(f"cannot build alert from service: {service_name}")
        raw = dict(source)
    elif check_type == "http":
        url = _optional_string(params.pop("url", None))
        if not url or urllib.parse.urlsplit(url).scheme not in {"http", "https"}:
            raise ModelManagerError("http alert requires an absolute HTTP(S) url=<地址>")
        check: dict[str, Any] = {"type": "http", "url": url}
        if "expectedStatus" in params:
            check["expectedStatus"] = _alert_int_list(
                params.pop("expectedStatus"), "expectedStatus"
            )
        if "bodyContains" in params:
            check["bodyContains"] = _alert_string_list(
                params.pop("bodyContains"), "bodyContains"
            )
        if "headers" in params:
            check["headers"] = _alert_json_object(params.pop("headers"), "headers")
        raw = {"description": f"告警管理添加：{name}", "check": check}
    elif check_type == "tcp":
        host = _optional_string(params.pop("host", None))
        if not host:
            raise ModelManagerError("tcp alert requires host=<主机>")
        try:
            port = int(str(params.pop("port", "")))
        except ValueError as exc:
            raise ModelManagerError("tcp alert requires a numeric port=<端口>") from exc
        if not 1 <= port <= 65535:
            raise ModelManagerError("tcp alert port must be between 1 and 65535")
        raw = {
            "description": f"告警管理添加：{name}",
            "check": {"type": "tcp", "host": host, "port": port},
        }
    else:
        command = params.pop("command", None)
        if command is None:
            raise ModelManagerError("command alert requires command=<命令或 JSON 数组>")
        check = {"type": "command", "command": _alert_command_list(command)}
        if "expectedExitCodes" in params:
            check["expectedExitCodes"] = _alert_int_list(
                params.pop("expectedExitCodes"), "expectedExitCodes"
            )
        if "stdoutContains" in params:
            check["stdoutContains"] = _alert_string_list(
                params.pop("stdoutContains"), "stdoutContains"
            )
        if "stderrContains" in params:
            check["stderrContains"] = _alert_string_list(
                params.pop("stderrContains"), "stderrContains"
            )
        raw = {"description": f"告警管理添加：{name}", "check": check}
    return _apply_alert_settings(raw, params)


def _apply_alert_settings(raw: dict[str, Any], values: Mapping[str, str]) -> dict[str, Any]:
    params = dict(values)
    if "description" in params:
        raw["description"] = str(params.pop("description"))
    raw.setdefault("description", "告警管理添加")
    if "intervalSeconds" in params:
        raw["intervalSeconds"] = _positive_float(
            params.pop("intervalSeconds"), "alert.intervalSeconds"
        )
    if "timeoutSeconds" in params:
        raw["timeoutSeconds"] = _positive_float(
            params.pop("timeoutSeconds"), "alert.timeoutSeconds"
        )
    if "severity" in params:
        severity = str(params.pop("severity")).strip().lower()
        if severity not in SEVERITIES:
            raise ModelManagerError("alert.severity must be info, warning, or critical")
        raw["severity"] = severity
    if "repeatAlertSeconds" in params:
        raw["repeatAlertSeconds"] = _non_negative_float(
            params.pop("repeatAlertSeconds"), "alert.repeatAlertSeconds"
        )
    if "notifyRecovery" in params:
        raw["notifyRecovery"] = _as_bool(
            params.pop("notifyRecovery"), "alert.notifyRecovery"
        )
    if "enabled" in params:
        raw["enabled"] = _as_bool(params.pop("enabled"), "alert.enabled")
    if params:
        raise ModelManagerError(
            f"unsupported alert parameter(s): {', '.join(sorted(params))}"
        )
    return raw


def _add_model(parameters: Mapping[str, str], context: ActionContext) -> ModelDefinition:
    values = dict(parameters)
    name = str(values.pop("name", "")).strip()
    node = _optional_string(values.pop("node", None))
    log_path = _optional_string(values.pop("logPath", None))
    patterns = values.pop("alertPatterns", None)
    if not name:
        raise ModelManagerError("model add requires name=<模型实例>")
    if not node:
        raise ModelManagerError("model add requires node=<节点名称>")
    if not log_path or not Path(log_path).is_absolute():
        raise ModelManagerError("model add requires an absolute logPath=<日志路径>")
    if patterns is None:
        raise ModelManagerError("model add requires alertPatterns=<关键字,...>")

    catalog = _load_catalog(context)
    if catalog.resolve(name) is not None:
        raise ModelManagerError(f"model already exists: {name}")

    raw: dict[str, Any] = {
        "description": str(values.pop("description", "")),
        "node": node,
        "logPath": log_path,
        "alertPatterns": _alert_string_list(str(patterns), "alertPatterns"),
    }
    if "monitorName" in values:
        raw["monitorName"] = str(values.pop("monitorName")).strip()
    for key in ("tailLines",):
        if key in values:
            raw[key] = _bounded_int(values.pop(key), f"model.{key}", 1, 1000)
    for key in ("intervalSeconds", "timeoutSeconds"):
        if key in values:
            raw[key] = _positive_float(values.pop(key), f"model.{key}")
    if "severity" in values:
        severity = str(values.pop("severity")).strip().lower()
        if severity not in SEVERITIES:
            raise ModelManagerError("model.severity must be info, warning, or critical")
        raw["severity"] = severity
    if "repeatAlertSeconds" in values:
        raw["repeatAlertSeconds"] = _non_negative_float(
            values.pop("repeatAlertSeconds"), "model.repeatAlertSeconds"
        )
    for key in ("notifyRecovery", "enabled"):
        if key in values:
            raw[key] = _as_bool(values.pop(key), f"model.{key}")
    if values:
        raise ModelManagerError(
            f"unsupported model parameter(s): {', '.join(sorted(values))}"
        )

    model = _parse_model(name, raw)
    if model.effective_monitor_name in set(_all_alerts(context)):
        raise ModelManagerError(
            f"monitor name already exists: {model.effective_monitor_name}"
        )
    nodes = context.require_service(NODES_SERVICE)
    if nodes.resolve(model.node, context) is None:
        raise ModelManagerError(f"unknown node: {model.node}")
    dynamic_models = load_models()
    dynamic_models[name] = raw
    save_models(dynamic_models)
    return model


def _format_model_added(model: ModelDefinition) -> str:
    patterns = ", ".join(f"`{pattern}`" for pattern in model.alert_patterns)
    return "\n".join(
        [
            "### 模型添加",
            "",
            f"- 模型：`{model.name}`",
            f"- 监控项：`{model.effective_monitor_name}`",
            f"- 节点：`{model.node}`",
            f"- 日志：`{model.log_path}`",
            f"- 关键字：{patterns}",
            f"- 间隔：**{model.interval_seconds:g}s**",
            f"- 存储：已写入 `{state_file()}`。",
            "- 生效：重启 `monitor` 后加载新监控。",
            f"- 验证：发送 `model check {model.name}`。",
        ]
    )


def _format_model_error(message: str) -> str:
    return "\n".join(
        [
            "### 模型添加失败",
            "",
            f"- 原因：{message}",
            "- 示例：`model add name=vllm-32 node=hangdian2-32 "
            "logPath=/data/applogs/vllm.log alertPatterns='Shutting down'`",
        ]
    )


def _parse_alert_parameters(tokens: Sequence[str]) -> dict[str, str]:
    return _parse_key_value_parameters(tokens, "alert")


def _parse_model_parameters(tokens: Sequence[str]) -> dict[str, str]:
    return _parse_key_value_parameters(tokens, "model")


def _parse_key_value_parameters(tokens: Sequence[str], label: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise ModelManagerError(f"invalid {label} parameter {token!r}; expected key=value")
        key, value = token.split("=", 1)
        key = key.strip()
        if not key:
            raise ModelManagerError(f"{label} parameter name must not be empty")
        if key in values:
            raise ModelManagerError(f"duplicate {label} parameter: {key}")
        values[key] = value
    return values


def _alert_string_list(value: str, label: str) -> list[str]:
    if value.strip().startswith("["):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ModelManagerError(f"{label} must be a JSON array") from exc
        if not isinstance(parsed, list):
            raise ModelManagerError(f"{label} must be a JSON array")
        return [str(item).strip() for item in parsed if str(item).strip()]
    return [item.strip() for item in value.split(",") if item.strip()]


def _alert_int_list(value: str, label: str) -> list[int]:
    try:
        return [int(item) for item in _alert_string_list(value, label)]
    except ValueError as exc:
        raise ModelManagerError(f"{label} must contain integers") from exc


def _alert_json_object(value: str, label: str) -> dict[str, str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ModelManagerError(f"{label} must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise ModelManagerError(f"{label} must be a JSON object")
    return {str(key): str(item) for key, item in parsed.items()}


def _alert_command_list(value: str) -> list[str]:
    text = value.strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ModelManagerError("command JSON is invalid") from exc
    else:
        try:
            parsed = shlex.split(text)
        except ValueError as exc:
            raise ModelManagerError(f"cannot parse command: {exc}") from exc
    if not isinstance(parsed, list) or not parsed or not all(
        isinstance(item, str) for item in parsed
    ):
        raise ModelManagerError("command must be a non-empty string array")
    return list(parsed)


def _format_alert_list(context: ActionContext) -> str:
    state = load_management()
    known = _all_alerts(context)
    if not known:
        return _format_alert_help()
    removed = set(state["removed"])
    disabled = set(state["disabled"])
    lines = [
        "### 告警管理",
        "",
        "| 告警项 | 类型 | 级别 | 间隔 | 状态 | 来源 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for name in sorted(known):
        item = known[name]
        check = item.get("check") if isinstance(item, Mapping) else None
        check_type = str(check.get("type", "")) if isinstance(check, Mapping) else ""
        severity = str(item.get("severity", "warning")) if isinstance(item, Mapping) else "warning"
        interval = item.get("intervalSeconds", 60) if isinstance(item, Mapping) else 60
        if name in removed:
            status = "已移出"
        elif name in disabled or not bool(item.get("enabled", True) if isinstance(item, Mapping) else True):
            status = "已关闭"
        else:
            status = "已启用"
        source = "动态添加" if name in state["added"] else "插件配置"
        lines.append(
            f"| `{name}` | `{check_type}` | {severity} | {float(interval):g}s | "
            f"{status} | {source} |"
        )
    lines.extend(
        [
            "",
            "提示：关闭保留定义；移出后可通过 `alert restore <名称>` 恢复。",
            "配置保存后在重启 `monitor` 时加载。",
        ]
    )
    return "\n".join(lines)


def _format_alert_change(
    action: str,
    names: Sequence[str],
    definition: Mapping[str, Any] | None = None,
) -> str:
    lines = [
        "### 告警管理",
        "",
        f"- 操作：**{action}**",
        f"- 数量：**{len(names)}**",
        f"- 告警项：{', '.join(f'`{name}`' for name in names)}",
    ]
    if definition is not None:
        check = definition.get("check")
        check_type = str(check.get("type", "")) if isinstance(check, Mapping) else ""
        lines.extend(
            [
                f"- 类型：`{check_type}`",
                f"- 级别：**{definition.get('severity', 'warning')}**",
                f"- 间隔：**{float(definition.get('intervalSeconds', 60)):g}s**",
            ]
        )
    if action == "关闭":
        lines.append("- 恢复：发送 `alert enable <名称>`")
    elif action == "移出":
        lines.append("- 恢复：发送 `alert restore <名称>`")
    lines.extend(
        [
            "- 生效：配置已保存，重启 `monitor` 后重新加载告警定义。",
            "- 说明：告警定义由 model-manager 插件管理，核心镜像无需更新。",
        ]
    )
    return "\n".join(lines)


def _format_alert_help(detail: str | None = None) -> str:
    details = {
        "model-log": [
            "监控 `models.json` 中某个模型实例的最近日志。",
            "`model` 是 `models` 下的实例键，例如 `vllm-31`；它决定节点、日志路径和关键字。",
            "必填：`model=<模型实例>`。",
            "示例：`alert add name=extra-vllm type=model-log model=vllm-31`",
        ],
        "node-service": [
            "监控 `models.json` 的 `services` 中声明的节点容器和 HTTP 状态。",
            "`service` 是 `services` 下的服务键，例如 `newapi-205`。",
            "必填：`service=<服务实例>`。",
            "示例：`alert add name=extra-service type=node-service service=newapi-205`",
        ],
        "http": [
            "直接发起 HTTP(S) 健康检查。",
            "必填：`url=<http(s)://地址>`。",
            "可选：`expectedStatus=200,204`、`bodyContains=ok`、`headers='{\"X-Key\":\"value\"}'`。",
            "示例：`alert add name=api-health type=http url=http://127.0.0.1:8080/health`",
        ],
        "tcp": [
            "检查 TCP 主机和端口是否可连接。",
            "必填：`host=<主机>`、`port=<端口>`。",
            "示例：`alert add name=redis-port type=tcp host=10.0.0.12 port=6379`",
        ],
        "command": [
            "执行本地命令并按退出码或输出判断结果。",
            "必填：`command=<命令或 JSON 数组>`。",
            "可选：`expectedExitCodes=0`、`stdoutContains=text`、`stderrContains=text`。",
            "示例：`alert add name=host-ready type=command command=hostname stdoutContains=worker`",
        ],
    }
    if detail:
        lines = details.get(detail)
        if lines is None:
            return _format_alert_error(
                f"unknown alert type: {detail}; use one of: {', '.join(sorted(details))}"
            )
        return "\n".join(
            [
                f"### 告警类型：{detail}",
                "",
                *[f"- {line}" for line in lines],
                "- 通用可选参数：`intervalSeconds`、`timeoutSeconds`、`severity`、"
                "`repeatAlertSeconds`、`notifyRecovery`、`enabled`、`description`。",
            ]
        )
    return "\n".join(
        [
            "### 告警管理",
            "",
            "- `alert list`：查看告警项和状态",
            "- `alert disable <名称,...>`：关闭告警项，保留定义",
            "- `alert enable <名称,...>`：重新启用告警项",
            "- `alert remove <名称,...>`：移出告警项",
            "- `alert restore <名称,...>`：恢复已移出告警项",
            "- `alert add name=<名称> type=<类型> [参数...]`：添加告警项",
            "- `alert help <类型>`：查看某类型的必填参数和示例",
            "",
            "支持类型：`model-log`、`node-service`、`http`、`tcp`、`command`。",
            "`model` 是 `models.json` 中 `models` 下的实例键，不是底层模型权重名称。",
            "配置保存后重启 `monitor` 生效；核心框架不需要修改。",
        ]
    )


def _format_alert_error(message: str) -> str:
    return "\n".join(
        [
            "### 告警管理失败",
            "",
            f"- 原因：{message}",
            "- 使用 `alert help` 查看命令格式。",
        ]
    )


def _load_catalog(
    context: ActionContext | None = None,
    *,
    include_dynamic: bool = True,
) -> ModelCatalog:
    source = _config_file()
    if source.is_file():
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ModelManagerError(f"cannot read model config {source}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ModelManagerError(f"model config {source} must be an object")
    else:
        raw = {}
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
    if include_dynamic:
        try:
            dynamic_models = load_models()
        except ModelStateError as exc:
            raise ModelManagerError(str(exc)) from exc
        for name, item in dynamic_models.items():
            if name in models:
                raise ModelManagerError(
                    f"dynamic model {name!r} conflicts with static model config"
                )
            models[name] = _parse_model(name, item)
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
        "| 模型 | 节点 | 日志 | 关键字 | 监控项 | 来源 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    dynamic_models = load_models()
    for model in sorted(catalog.models.values(), key=lambda item: item.name):
        patterns = ", ".join(f"`{pattern}`" for pattern in model.alert_patterns)
        source = "动态添加" if model.name in dynamic_models else "插件配置"
        lines.append(
            f"| `{model.name}` | `{model.node}` | `{model.log_path}` | "
            f"{patterns} | `{model.effective_monitor_name}` | {source} |"
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
                "尚未配置模型。可填写 `config/models.json`、设置 `MODEL_MANAGER_CONFIG`，或发送 `model add`。",
                "- `model add name=<名称> node=<节点> logPath=<路径> alertPatterns=<关键字>`：添加模型",
                "- `alert help`：查看告警管理命令",
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
            "- `model add name=<名称> node=<节点> logPath=<路径> alertPatterns=<关键字>`：添加模型",
            "- `alert list`：查看告警项状态",
            "- `alert disable|enable|remove|restore <名称,...>`：管理告警项",
            "- `alert add name=<名称> type=<类型> [参数...]`：添加告警项",
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
