from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from dingtalk_ops_bridge.action_api import ActionContext, ActionValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PLUGIN_ROOT = PROJECT_ROOT / "plugins" / "model-manager"


class FakeNodes:
    def __init__(self, known=("web-01",)):
        self.known = set(known)
        self.last_remote = ""

    def resolve(self, name, context):
        return SimpleNamespace(name=name) if name in self.known else None

    def ssh_command(self, name, remote_command, context):
        self.last_remote = remote_command
        return SimpleNamespace(
            argv=("ssh", f"ops@{name}", remote_command),
            env={},
            node=SimpleNamespace(name=name, host="10.0.0.11"),
        )


class ModelManagerPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source_dir = str(PLUGIN_ROOT / "src")
        if source_dir not in sys.path:
            sys.path.insert(0, source_dir)
        cls.plugin = importlib.import_module("model_manager_plugin")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "models.json"
        self.alert_state = self.root / "alert-management.json"
        self.model_state = self.root / "model-state.json"
        self.nodes = FakeNodes()
        self.context = ActionContext(services={"nodes": self.nodes})
        self.state_env = mock.patch.dict(
            os.environ,
            {
                "MODEL_MANAGER_ALERT_STATE_FILE": str(self.alert_state),
                "MODEL_MANAGER_MODEL_STATE_FILE": str(self.model_state),
            },
        )
        self.state_env.start()
        self.addCleanup(self.state_env.stop)
        self.config.write_text(
            json.dumps(
                {
                    "models": {
                        "vllm-27": {
                            "node": "web-01",
                            "logPath": "/data/applogs/vllm.log",
                            "tailLines": 10,
                            "alertPatterns": ["No available shared memory broadcast"],
                            "monitorName": "vllm-shared-memory-27",
                        }
                    },
                    "services": {
                        "newapi-205": {
                            "node": "web-01",
                            "container": "new-api",
                            "url": "http://127.0.0.1:3000/api/status",
                            "expectedStatus": 200,
                            "monitorName": "newapi-status-205",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_monitor_definitions_are_generated_from_model_config(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            monitors = self.plugin.MONITOR_PROVIDER.monitors(self.context)
        monitor = monitors["vllm-shared-memory-27"]
        self.assertEqual(monitor["check"], {"type": "model-log", "model": "vllm-27"})
        self.assertEqual(monitor["severity"], "critical")
        self.assertEqual(monitor["intervalSeconds"], 60)
        self.assertTrue(monitor["enabled"])

    def test_unknown_node_fails_monitor_loading(self):
        self.nodes.known.clear()
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with self.assertRaisesRegex(ActionValidationError, "unknown node"):
                self.plugin.MONITOR_PROVIDER.monitors(self.context)

    def test_check_detects_alert_pattern_in_last_lines(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(
                    1,
                    "",
                    "No available shared memory broadcast: rank 0",
                    False,
                    12,
                )
                result = self.plugin.MONITOR_PROVIDER.check(
                    {"model": "vllm-27"}, self.context
                )
        self.assertFalse(result.ok)
        self.assertIn("命中异常关键字", result.message)
        self.assertIn("No available shared memory", result.details)
        self.assertIn("tail -n 10", self.nodes.last_remote)
        self.assertIn("grep -Fq", self.nodes.last_remote)

    def test_check_reports_healthy_log(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(0, "", "", False, 8)
                result = self.plugin.MONITOR_PROVIDER.check(
                    {"model": "vllm-27"}, self.context
                )
        self.assertTrue(result.ok)
        self.assertIn("未命中", result.message)

    def test_model_list_command_outputs_monitor_name(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            output = self.plugin.COMMAND_PROVIDER.handle("model list", self.context)
        self.assertIn("模型清单", output)
        self.assertIn("vllm-27", output)
        self.assertIn("vllm-shared-memory-27", output)
        self.assertIn("服务监控", output)
        self.assertIn("newapi-205", output)
        self.assertIn("newapi-status-205", output)

    def test_model_add_persists_dynamic_model_and_generates_monitor(self):
        command = (
            "model add name=vllm-32 node=web-01 "
            "logPath=/data/applogs/vllm.log "
            "alertPatterns='Shutting down,No available shared memory broadcast' "
            "description='32 节点 vLLM 日志' intervalSeconds=30 timeoutSeconds=9 "
            "severity=warning repeatAlertSeconds=120 notifyRecovery=false"
        )
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            output = self.plugin.COMMAND_PROVIDER.handle(command, self.context)
            listed = self.plugin.COMMAND_PROVIDER.handle("model list", self.context)
            monitors = self.plugin.MONITOR_PROVIDER.monitors(self.context)
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(0, "", "", False, 8)
                result = self.plugin.MONITOR_PROVIDER.check(
                    {"model": "vllm-32"}, self.context
                )

        self.assertIn("模型添加", output)
        self.assertIn("model-manager-vllm-32-log", output)
        self.assertIn(str(self.model_state), output)
        self.assertIn("重启 `monitor`", output)
        self.assertIn("vllm-32", listed)
        self.assertIn("动态添加", listed)
        monitor = monitors["model-manager-vllm-32-log"]
        self.assertEqual(monitor["check"], {"type": "model-log", "model": "vllm-32"})
        self.assertEqual(monitor["intervalSeconds"], 30.0)
        self.assertEqual(monitor["timeoutSeconds"], 9.0)
        self.assertEqual(monitor["severity"], "warning")
        self.assertEqual(monitor["repeatAlertSeconds"], 120.0)
        self.assertFalse(monitor["notifyRecovery"])
        self.assertTrue(result.ok)
        self.assertIn("tail -n 10", self.nodes.last_remote)
        self.assertIn("Shutting down", self.nodes.last_remote)

        state = json.loads(self.model_state.read_text(encoding="utf-8"))
        self.assertEqual(state["version"], 1)
        entry = state["models"]["vllm-32"]
        self.assertEqual(entry["node"], "web-01")
        self.assertEqual(entry["logPath"], "/data/applogs/vllm.log")
        self.assertEqual(
            entry["alertPatterns"],
            ["Shutting down", "No available shared memory broadcast"],
        )
        self.assertEqual(entry["intervalSeconds"], 30.0)
        self.assertEqual(entry["severity"], "warning")
        self.assertFalse(entry["notifyRecovery"])

    def test_model_add_rejects_duplicate_names_and_monitor_conflicts(self):
        base = "node=web-01 logPath=/data/applogs/vllm.log alertPatterns='Shutting down'"
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            static_duplicate = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=vllm-27 {base}", self.context
            )
            added = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=vllm-32 {base}", self.context
            )
            dynamic_duplicate = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=vllm-32 {base}", self.context
            )
            casefold_duplicate = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=VLLM-32 {base}", self.context
            )
            model_monitor_conflict = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=vllm-33 {base} "
                "monitorName=vllm-shared-memory-27",
                self.context,
            )
            service_monitor_conflict = self.plugin.COMMAND_PROVIDER.handle(
                f"model add name=vllm-34 {base} monitorName=newapi-status-205",
                self.context,
            )

        self.assertIn("already exists", static_duplicate)
        self.assertIn("模型添加", added)
        self.assertIn("already exists", dynamic_duplicate)
        self.assertIn("already exists", casefold_duplicate)
        self.assertIn("monitor name already exists", model_monitor_conflict)
        self.assertIn("monitor name already exists", service_monitor_conflict)
        state = json.loads(self.model_state.read_text(encoding="utf-8"))
        self.assertEqual(sorted(state["models"]), ["vllm-32"])

    def test_model_add_validates_required_fields_and_node(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            cases = [
                ("model add", "name=<模型实例>"),
                ("model add name=vllm-32", "node=<节点名称>"),
                ("model add name=vllm-32 node=web-01", "logPath=<日志路径>"),
                (
                    "model add name=vllm-32 node=web-01 "
                    "logPath=/data/applogs/vllm.log",
                    "alertPatterns=<关键字,...>",
                ),
                (
                    "model add name=vllm-32 node=missing "
                    "logPath=/data/applogs/vllm.log alertPatterns=boom",
                    "unknown node",
                ),
            ]
            for command, expected in cases:
                with self.subTest(command=command):
                    output = self.plugin.COMMAND_PROVIDER.handle(command, self.context)
                    self.assertIn("模型添加失败", output)
                    self.assertIn(expected, output)

        self.assertFalse(self.model_state.exists())

    def test_service_monitor_definitions_are_generated_from_config(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            monitors = self.plugin.SERVICE_MONITOR_PROVIDER.monitors(self.context)
        monitor = monitors["newapi-status-205"]
        self.assertEqual(
            monitor["check"],
            {"type": "node-service", "service": "newapi-205"},
        )
        self.assertEqual(monitor["severity"], "critical")
        self.assertEqual(monitor["intervalSeconds"], 60)
        self.assertTrue(monitor["enabled"])

    def test_service_monitor_rejects_unknown_node(self):
        self.nodes.known.clear()
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with self.assertRaisesRegex(ActionValidationError, "unknown node"):
                self.plugin.SERVICE_MONITOR_PROVIDER.monitors(self.context)

    def test_alert_disable_enable_remove_restore_and_add(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            output = self.plugin.COMMAND_PROVIDER.handle(
                "alert disable vllm-shared-memory-27,newapi-status-205",
                self.context,
            )
            self.assertIn("关闭", output)
            self.assertFalse(
                self.plugin.MONITOR_PROVIDER.monitors(self.context)[
                    "vllm-shared-memory-27"
                ]["enabled"]
            )
            self.assertFalse(
                self.plugin.SERVICE_MONITOR_PROVIDER.monitors(self.context)[
                    "newapi-status-205"
                ]["enabled"]
            )

            self.assertIn(
                "启用",
                self.plugin.COMMAND_PROVIDER.handle(
                    "alert enable vllm-shared-memory-27,newapi-status-205",
                    self.context,
                ),
            )
            self.assertTrue(
                self.plugin.MONITOR_PROVIDER.monitors(self.context)[
                    "vllm-shared-memory-27"
                ]["enabled"]
            )

            self.plugin.COMMAND_PROVIDER.handle(
                "alert remove vllm-shared-memory-27", self.context
            )
            self.assertNotIn(
                "vllm-shared-memory-27",
                self.plugin.MONITOR_PROVIDER.monitors(self.context),
            )
            self.plugin.COMMAND_PROVIDER.handle(
                "alert restore vllm-shared-memory-27", self.context
            )
            self.assertIn(
                "vllm-shared-memory-27",
                self.plugin.MONITOR_PROVIDER.monitors(self.context),
            )

            added = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=vllm-31-copy type=model-log model=vllm-27 "
                "intervalSeconds=30 severity=warning",
                self.context,
            )
            self.assertIn("添加", added)
            monitors = self.plugin.MONITOR_PROVIDER.monitors(self.context)
            self.assertIn("vllm-31-copy", monitors)
            self.assertEqual(monitors["vllm-31-copy"]["check"]["model"], "vllm-27")
            self.assertEqual(monitors["vllm-31-copy"]["intervalSeconds"], 30.0)
            self.assertEqual(monitors["vllm-31-copy"]["severity"], "warning")

            http_output = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=api-health type=http "
                "url=http://127.0.0.1:8080/health expectedStatus=200,204",
                self.context,
            )
            self.assertIn("添加", http_output)
            http_monitor = self.plugin.MONITOR_PROVIDER.monitors(self.context)[
                "api-health"
            ]
            self.assertEqual(http_monitor["check"]["type"], "http")
            self.assertEqual(http_monitor["check"]["expectedStatus"], [200, 204])

            service_output = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=service-copy type=node-service service=newapi-205",
                self.context,
            )
            self.assertIn("添加", service_output)
            self.assertIn(
                "service-copy",
                self.plugin.SERVICE_MONITOR_PROVIDER.monitors(self.context),
            )

            command_output = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=host-ready type=command command=hostname "
                "stdoutContains=worker",
                self.context,
            )
            self.assertIn("添加", command_output)
            command_monitor = self.plugin.MONITOR_PROVIDER.monitors(self.context)[
                "host-ready"
            ]
            self.assertEqual(command_monitor["check"]["command"], ["hostname"])

            self.plugin.COMMAND_PROVIDER.handle("alert remove api-health", self.context)
            self.assertNotIn(
                "api-health", self.plugin.MONITOR_PROVIDER.monitors(self.context)
            )
            self.plugin.COMMAND_PROVIDER.handle("alert restore api-health", self.context)
            self.assertIn(
                "api-health", self.plugin.MONITOR_PROVIDER.monitors(self.context)
            )

        state = json.loads(self.alert_state.read_text(encoding="utf-8"))
        self.assertIn("vllm-31-copy", state["added"])
        self.assertIn("api-health", state["added"])

    def test_alert_add_rejects_duplicates_and_invalid_types(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            duplicate = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=vllm-shared-memory-27 type=model-log model=vllm-27",
                self.context,
            )
            self.assertIn("already exists", duplicate)

            self.plugin.COMMAND_PROVIDER.handle(
                "alert remove vllm-shared-memory-27", self.context
            )
            removed = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=vllm-shared-memory-27 type=model-log model=vllm-27",
                self.context,
            )
            self.assertIn("restore it first", removed)

            missing_type = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=missing", self.context
            )
            self.assertIn("requires type", missing_type)
            invalid_type = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=bad type=unknown", self.context
            )
            self.assertIn("type must be one of", invalid_type)
            unknown_model = self.plugin.COMMAND_PROVIDER.handle(
                "alert add name=bad type=model-log model=missing", self.context
            )
            self.assertIn("unknown model", unknown_model)

    def test_alert_list_shows_management_status(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            self.plugin.COMMAND_PROVIDER.handle(
                "alert disable vllm-shared-memory-27", self.context
            )
            output = self.plugin.COMMAND_PROVIDER.handle("alert list", self.context)
        self.assertIn("vllm-shared-memory-27", output)
        self.assertIn("已关闭", output)
        self.assertIn("插件配置", output)
        self.assertIn("重启 `monitor`", output)

    def test_alert_help_describes_type_parameters(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            summary = self.plugin.COMMAND_PROVIDER.handle(
                "alert help", self.context
            )
            model_help = self.plugin.COMMAND_PROVIDER.handle(
                "alert help model-log", self.context
            )
            http_help = self.plugin.COMMAND_PROVIDER.handle(
                "alert describe http", self.context
            )
            unknown = self.plugin.COMMAND_PROVIDER.handle(
                "alert help unknown", self.context
            )
        self.assertIn("`alert help <类型>`", summary)
        self.assertIn("不是底层模型权重名称", summary)
        self.assertIn("models.json", model_help)
        self.assertIn("model=<模型实例>", model_help)
        self.assertIn("url=<http(s)://地址>", http_help)
        self.assertIn("unknown alert type", unknown)

    def test_service_check_reports_healthy_container_and_http_endpoint(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(0, "", "", False, 8)
                result = self.plugin.SERVICE_MONITOR_PROVIDER.check(
                    {"service": "newapi-205"}, self.context
                )
        self.assertTrue(result.ok)
        self.assertIn("服务状态正常", result.message)
        self.assertIn("docker inspect -f '{{.State.Running}}' new-api", self.nodes.last_remote)
        self.assertIn("curl -sS --max-time 5", self.nodes.last_remote)
        self.assertIn("http://127.0.0.1:3000/api/status", self.nodes.last_remote)

    def test_service_check_reports_stopped_container(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(
                    3, "", "container not running: new-api", False, 8
                )
                result = self.plugin.SERVICE_MONITOR_PROVIDER.check(
                    {"service": "newapi-205"}, self.context
                )
        self.assertFalse(result.ok)
        self.assertIn("容器未运行", result.message)
        self.assertIn("container not running", result.details)

    def test_service_check_reports_unexpected_http_status(self):
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with mock.patch.object(self.plugin, "_run_process") as run:
                run.return_value = self.plugin._ProcessResult(
                    5, "", "unexpected HTTP status: 503", False, 8
                )
                result = self.plugin.SERVICE_MONITOR_PROVIDER.check(
                    {"service": "newapi-205"}, self.context
                )
        self.assertFalse(result.ok)
        self.assertIn("HTTP 状态异常", result.message)
        self.assertIn("503", result.details)

    def test_service_config_requires_container_or_url(self):
        self.config.write_text(
            json.dumps(
                {
                    "models": {},
                    "services": {"broken": {"node": "web-01"}},
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with self.assertRaisesRegex(ActionValidationError, "container.*url"):
                self.plugin._load_catalog(self.context)

    def test_model_config_requires_absolute_log_path(self):
        self.config.write_text(
            json.dumps(
                {
                    "models": {
                        "bad": {
                            "node": "web-01",
                            "logPath": "relative/vllm.log",
                            "alertPatterns": ["boom"],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"MODEL_MANAGER_CONFIG": str(self.config)}):
            with self.assertRaisesRegex(ActionValidationError, "absolute 'logPath'"):
                self.plugin._load_catalog(self.context)


if __name__ == "__main__":
    unittest.main()
