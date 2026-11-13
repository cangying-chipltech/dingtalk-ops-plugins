from __future__ import annotations

import json
import os
import re
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


PLUGIN_ROOT = Path(__file__).resolve().parents[2]
NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
STRICT_HOST_KEY_VALUES = {"yes", "no", "accept-new"}
NODE_COMMANDS = {"nodes", "node", "节点"}
LIST_COMMANDS = {"list", "列表"}


class NodePluginError(ActionValidationError):
    """Raised when node configuration or execution is invalid."""


@dataclass(frozen=True)
class NodeDefinition:
    name: str
    host: str
    user: str
    port: int = 22
    password_env: str | None = None
    password_file: str | None = None
    identity_file: str | None = None
    known_hosts_file: str | None = None
    strict_host_key_checking: str = "accept-new"
    connect_timeout_seconds: int = 10
    description: str = ""

    @property
    def auth_method(self) -> str:
        methods: list[str] = []
        if self.password_env:
            methods.append("password-env")
        if self.password_file:
            methods.append("password-file")
        if self.identity_file:
            methods.append("key")
        return "+".join(methods) if methods else "ssh-agent/default-key"

    def ssh_command(self, remote_command: str) -> tuple[tuple[str, ...], dict[str, str]]:
        known_hosts = self.known_hosts_file or str(_data_dir() / "known_hosts")
        args: list[str] = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            f"ConnectTimeout={self.connect_timeout_seconds}",
            "-o",
            f"StrictHostKeyChecking={self.strict_host_key_checking}",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "LogLevel=ERROR",
        ]
        if self.identity_file:
            args.extend(["-i", self.identity_file])
        uses_password = bool(self.password_env or self.password_file)
        if not uses_password:
            args.extend(["-o", "BatchMode=yes"])
        args.extend([f"{self.user}@{self.host}", remote_command])

        if self.password_env:
            return ("sshpass", "-e", *args), {"SSHPASS": f"${{{self.password_env}}}"}
        if self.password_file:
            return ("sshpass", "-f", self.password_file, *args), {}
        return tuple(args), {}

    def to_info(self) -> "NodeInfo":
        return NodeInfo(
            name=self.name,
            host=self.host,
            user=self.user,
            port=self.port,
            description=self.description,
            auth_method=self.auth_method,
        )


@dataclass(frozen=True)
class NodeInfo:
    name: str
    host: str
    user: str
    port: int
    description: str = ""
    auth_method: str = "ssh-agent/default-key"


@dataclass(frozen=True)
class SshCommand:
    argv: tuple[str, ...]
    env: Mapping[str, str]
    node: NodeInfo


@dataclass(frozen=True)
class NodeCatalog:
    nodes: Mapping[str, NodeDefinition] = field(default_factory=dict)


class NodeService:
    api_version = PLUGIN_API_VERSION

    def list_nodes(self, context: ActionContext) -> tuple[NodeInfo, ...]:
        catalog = _load_catalog(context)
        return tuple(node.to_info() for node in catalog.nodes.values())

    def resolve(self, name: str, context: ActionContext) -> NodeInfo | None:
        catalog = _load_catalog(context)
        node = catalog.nodes.get(str(name))
        return node.to_info() if node is not None else None

    def ssh_command(
        self,
        name: str,
        remote_command: str,
        context: ActionContext,
    ) -> SshCommand:
        catalog = _load_catalog(context)
        node = catalog.nodes.get(str(name))
        if node is None:
            raise ActionValidationError(
                f"unknown node: {name!r}; configure it in plugins/nodes/config/nodes.json"
            )
        if node.password_env and not os.getenv(node.password_env):
            raise ActionValidationError(
                f"node {name!r} password environment variable {node.password_env} is not set"
            )
        if node.password_file and not Path(node.password_file).is_file():
            raise ActionValidationError(
                f"node {name!r} password file does not exist: {node.password_file}"
            )
        command, env = node.ssh_command(remote_command)
        return SshCommand(argv=command, env=env, node=node.to_info())


class NodeActionProvider:
    api_version = PLUGIN_API_VERSION
    type_name = "node"

    def validate(self, definition: ActionDefinition) -> None:
        remote_command = str(definition.config.get("remoteCommand", "")).strip()
        if not remote_command:
            raise ActionValidationError(
                f"node action {definition.name!r} requires a non-empty 'remoteCommand'"
            )
        node_parameter = definition.parameters.get("node")
        if node_parameter is None or node_parameter.kind != "node":
            raise ActionValidationError(
                f"node action {definition.name!r} requires parameter 'node' with type 'node'"
            )
        if node_parameter.pattern is not None:
            raise ActionValidationError(
                f"node action {definition.name!r} parameter 'node' cannot use a pattern"
            )
        extra = sorted(set(definition.parameters) - {"node"})
        if extra:
            raise ActionValidationError(
                f"node action {definition.name!r} only supports a 'node' parameter; got: {', '.join(extra)}"
            )

    def prepare(
        self,
        definition: ActionDefinition,
        values: Mapping[str, str],
        context: ActionContext,
    ) -> PreparedAction:
        resolved = definition.resolved_values(values)
        node_name = resolved.get("node", "")
        node_command = SERVICE.ssh_command(
            node_name,
            str(definition.config["remoteCommand"]),
            context,
        )
        return PreparedAction(
            definition=definition,
            command=node_command.argv,
            env={**definition.env, **node_command.env},
        )


class NodeCommandProvider:
    api_version = PLUGIN_API_VERSION
    command_prefixes = tuple(sorted(NODE_COMMANDS))

    def handle(self, prompt: str, context: ActionContext) -> str | None:
        text = (prompt or "").strip()
        if not text:
            return None
        parts = text.split(maxsplit=1)
        if parts[0].lower() not in NODE_COMMANDS:
            return None
        rest = parts[1].strip() if len(parts) > 1 else ""
        tokens = rest.split(maxsplit=1)
        if tokens and tokens[0].lower() not in LIST_COMMANDS:
            raise NodePluginError("节点命令格式为 `nodes`、`node list` 或 `节点`。")
        return _format_node_list(SERVICE.list_nodes(context))

    def help_lines(self) -> Sequence[str]:
        return (
            "- `nodes` / `node list` / `节点`：列出节点插件中的节点，不显示密码",
        )


def _config_path(context: ActionContext) -> Path:
    for name in ("NODES_CONFIG", "NODES_FILE"):
        configured = os.getenv(name)
        if configured:
            return Path(configured).expanduser()
    config_dir = context.resources.get(RESOURCE_CONFIG_DIR)
    if config_dir:
        candidate = Path(str(config_dir)) / "nodes.json"
        if candidate.exists():
            return candidate
    return PLUGIN_ROOT / "config" / "nodes.json"


def _load_catalog(context: ActionContext) -> NodeCatalog:
    source = _config_path(context)
    if not source.exists():
        return NodeCatalog()
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NodePluginError(f"cannot read nodes file {source}: {exc}") from exc
    if not isinstance(raw, dict):
        raise NodePluginError("nodes config root must be an object")

    nodes_raw = raw.get("nodes", {})
    if not isinstance(nodes_raw, dict):
        raise NodePluginError("'nodes' must be an object")

    nodes: dict[str, NodeDefinition] = {}
    for name, item in nodes_raw.items():
        if not isinstance(item, dict):
            raise NodePluginError(f"node {name!r} must be an object")
        if NODE_NAME_RE.fullmatch(name) is None:
            raise NodePluginError(
                f"invalid node name {name!r}; use letters, digits, dot, underscore or dash"
            )
        for forbidden in ("password", "passphrase", "secret"):
            if forbidden in item:
                raise NodePluginError(
                    f"node {name!r} must not contain {forbidden!r}; use passwordEnv "
                    "or passwordFile"
                )

        host = str(item.get("host", "")).strip()
        user = str(item.get("user", "")).strip()
        if not host or not user:
            raise NodePluginError(f"node {name!r} requires 'host' and 'user'")
        try:
            port = int(item.get("port", 22))
        except (TypeError, ValueError) as exc:
            raise NodePluginError(f"node {name!r} port must be an integer") from exc
        if not 1 <= port <= 65535:
            raise NodePluginError(f"node {name!r} port must be between 1 and 65535")

        password_env = _optional_string(item.get("passwordEnv"))
        if password_env and ENV_NAME_RE.fullmatch(password_env) is None:
            raise NodePluginError(
                f"node {name!r} passwordEnv must be a valid environment variable name"
            )
        password_file = _resolve_optional_path(source.parent, item.get("passwordFile"))
        if password_env and password_file:
            raise NodePluginError(
                f"node {name!r} must use only one of passwordEnv or passwordFile"
            )
        identity_file = _resolve_optional_path(source.parent, item.get("identityFile"))
        known_hosts_file = _resolve_optional_path(source.parent, item.get("knownHostsFile"))
        strict = str(item.get("strictHostKeyChecking", "accept-new")).lower()
        if strict not in STRICT_HOST_KEY_VALUES:
            raise NodePluginError(
                f"node {name!r} strictHostKeyChecking must be one of: yes, no, accept-new"
            )
        try:
            connect_timeout = int(item.get("connectTimeoutSeconds", 10))
        except (TypeError, ValueError) as exc:
            raise NodePluginError(
                f"node {name!r} connectTimeoutSeconds must be an integer"
            ) from exc
        if connect_timeout <= 0:
            raise NodePluginError(
                f"node {name!r} connectTimeoutSeconds must be greater than zero"
            )

        nodes[name] = NodeDefinition(
            name=name,
            host=host,
            user=user,
            port=port,
            password_env=password_env,
            password_file=password_file,
            identity_file=identity_file,
            known_hosts_file=known_hosts_file,
            strict_host_key_checking=strict,
            connect_timeout_seconds=connect_timeout,
            description=str(item.get("description", "")),
        )
    return NodeCatalog(nodes=nodes)


def _format_node_list(nodes: Sequence[NodeInfo]) -> str:
    if not nodes:
        return "\n".join(
            [
                "### 节点清单",
                "",
                "尚未配置节点。复制 `plugins/nodes/config/nodes.example.json` 为",
                "`plugins/nodes/config/nodes.json` 后填写主机信息。",
            ]
        )
    lines = [
        "### 节点清单",
        "",
        "| 名称 | 主机 | 用户 | 端口 | 认证 | 说明 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for node in sorted(nodes, key=lambda item: item.name):
        description = (node.description or "-").replace("|", "\\|").replace("\n", " ")
        lines.append(
            f"| `{node.name}` | `{node.host}` | `{node.user}` | `{node.port}` | "
            f"{node.auth_method} | {description} |"
        )
    lines.extend(["", "使用示例：`run node-login node=web-01`。"])
    return "\n".join(lines)


def _data_dir() -> Path:
    configured = os.getenv("DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    container_dir = Path("/app/data")
    if container_dir.is_dir():
        return container_dir
    return PLUGIN_ROOT / "data"


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _resolve_optional_path(base: Path, value: Any) -> str | None:
    text = _optional_string(value)
    if not text:
        return None
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base / path
    return str(path.resolve())


SERVICE = NodeService()
PROVIDER = NodeActionProvider()
COMMAND_PROVIDER = NodeCommandProvider()
