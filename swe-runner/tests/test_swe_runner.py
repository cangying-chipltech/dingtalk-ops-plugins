from __future__ import annotations

import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dingtalk_ops_bridge.action_api import ActionContext
from dingtalk_ops_bridge.actions import execute_actions, load_action_catalog
from dingtalk_ops_bridge.action_types import build_default_registry
from dingtalk_ops_bridge.commands import format_help, handle_prompt
from dingtalk_ops_bridge.util import ProcessResult


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PLUGIN_DIR = PROJECT_ROOT / "plugins"


class SweRunnerPluginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with mock.patch.dict(os.environ, {"ACTION_PLUGIN_DIR": str(PLUGIN_DIR)}):
            cls.registry = build_default_registry()
        cls.plugin = importlib.import_module("swe_runner_plugin")

    def test_load_and_resolve_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write_config(Path(tmp))
            with mock.patch.dict(os.environ, {"SWE_RUNNER_CONFIG": str(path)}):
                catalog = self.plugin._load_catalog(ActionContext())
            self.assertEqual(catalog.default_target().name, "69")
            self.assertEqual(catalog.resolve("10.0.10.69").name, "69")
            self.assertEqual(catalog.resolve("69").name, "69")

    def test_command_provider_declares_routes_and_single_fallback(self):
        prefixes = self.registry.command_prefixes()
        self.assertIn("swe-runner", prefixes)
        for prefix in ("status", "query", "history", "recent"):
            self.assertNotIn(prefix, prefixes)
        fallback = self.registry.command_fallback()
        self.assertIsNotNone(fallback)
        self.assertIs(fallback.provider, self.plugin.COMMAND_PROVIDER)

    def test_remote_command_and_history(self):
        target = self.plugin.SweTarget(
            name="69",
            host="10.0.10.69",
            queue="queue value",
            user="test",
            remote_dir="/opt/swe runner",
        )
        command = target.remote_command(True)
        self.assertIn("cd '/opt/swe runner'", command)
        self.assertIn("'queue value' --verbose --history", command)

    def test_status_metrics_are_parsed(self):
        target = self.plugin.SweTarget(name="69", host="10.0.10.69", queue="q", user="test")
        raw = "\n".join(
            [
                "Total tasks: 10",
                "Running: 2",
                "Completed: 8 (success=7, failed=1)",
                "Progress: 80.0%",
                "Success rate: 87.5%",
            ]
        )
        process = self.plugin._ProcessResult(0, raw, "", False, 123)
        output = self.plugin._format_status(
            target, False, process, self.plugin.SweRunnerSettings()
        )
        self.assertIn("total: 10", output)
        self.assertIn("completed: 8 (success=7, failed=1)", output)
        self.assertIn("progress: 80.0%", output)
        self.assertIn("success rate: 87.5%", output)

    def test_command_plugin_uses_namespace_and_keeps_framework_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self._write_config(root)
            catalog = load_action_catalog(self._write_actions(root), registry=self.registry)
            monitors_path = self._write_monitors(root)
            process = self.plugin._ProcessResult(0, "Total tasks: 1\n", "", False, 8)

            with mock.patch.dict(os.environ, {"SWE_RUNNER_CONFIG": str(config_path)}), mock.patch.object(
                self.plugin, "_run_process", return_value=process
            ) as run_process:
                for prompt in (
                    "swe-runner status",
                    "swe-runner query",
                    "swe-runner s",
                    "swe-runner q",
                    "swe-runner check",
                    "swe-runner 69 check",
                    "69 status",
                ):
                    output = handle_prompt(prompt, catalog, monitors_path=monitors_path)
                    self.assertIn("swe-runner status - 69", output, prompt)
                    self.assertNotIn("--history", run_process.call_args.args[0][-1], prompt)

                for prompt in (
                    "swe-runner history",
                    "swe-runner recent",
                    "swe-runner 69 history",
                    "69 history",
                ):
                    output = handle_prompt(prompt, catalog, monitors_path=monitors_path)
                    self.assertIn("swe-runner history - 69", output, prompt)
                    self.assertIn("--history", run_process.call_args.args[0][-1], prompt)

                output = handle_prompt("status", catalog, monitors_path=monitors_path)
                self.assertIn("监控检查结果", output)
                output = handle_prompt("check", catalog, monitors_path=monitors_path)
                self.assertIn("监控检查结果", output)

    def test_namespaced_status_does_not_change_framework_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "swe-runner.json"
            config_path.write_text(
                json.dumps(
                    {
                        "targets": {
                            "69": {
                                "host": "10.0.10.69",
                                "queue": "queue-69",
                                "user": "test",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            catalog = load_action_catalog(self._write_actions(root), registry=self.registry)
            monitors_path = self._write_monitors(root)
            with mock.patch.dict(os.environ, {"SWE_RUNNER_CONFIG": str(config_path)}):
                plugin_output = handle_prompt(
                    "swe-runner status", catalog, monitors_path=monitors_path
                )
                status_output = handle_prompt("status", catalog, monitors_path=monitors_path)
                check_output = handle_prompt("check", catalog, monitors_path=monitors_path)
            self.assertIn("需要先配置 swe-runner 默认目标", plugin_output)
            self.assertIn("监控检查结果", status_output)
            self.assertIn("监控检查结果", check_output)

    def test_swe_runner_action_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = self._write_config(root)
            action_path = root / "actions.json"
            action_path.write_text(
                json.dumps(
                    {
                        "actions": {
                            "swe-history": {
                                "type": "swe-runner",
                                "target": "69",
                                "history": True,
                                "timeoutSeconds": 12,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            action_catalog = load_action_catalog(action_path, registry=self.registry)
            process = ProcessResult(0, "Total tasks: 1\n", "", False, 8)
            with mock.patch.dict(os.environ, {"SWE_RUNNER_CONFIG": str(config_path)}), mock.patch(
                "dingtalk_ops_bridge.actions.run_process", return_value=process
            ) as run_process:
                execution = execute_actions(
                    action_catalog,
                    ("swe-history",),
                    {},
                    context=ActionContext(),
                )
            self.assertTrue(execution.results[0].ok)
            command = run_process.call_args.args[0]
            self.assertIn("./status_swebench.sh", command[-1])
            self.assertIn("queue-69", command[-1])
            self.assertIn("--history", command[-1])
            self.assertEqual(run_process.call_args.kwargs["timeout_seconds"], 12)

    def test_target_can_resolve_connection_from_nodes_plugin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            swe_config = root / "swe-runner.json"
            swe_config.write_text(
                json.dumps(
                    {
                        "default": "69",
                        "targets": {
                            "69": {
                                "node": "swe-69",
                                "queue": "queue-69",
                                "remoteDir": "/opt/swe-runner",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            nodes_config = root / "nodes.json"
            nodes_config.write_text(
                json.dumps(
                    {
                        "nodes": {
                            "swe-69": {
                                "host": "10.0.0.70",
                                "user": "ops",
                                "passwordEnv": "TEST_NODE_PASSWORD",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            action_path = root / "actions.json"
            action_path.write_text(
                json.dumps({"actions": {"swe-status": {"type": "swe-runner", "target": "69"}}}),
                encoding="utf-8",
            )
            action_catalog = load_action_catalog(action_path, registry=self.registry)
            process = ProcessResult(0, "Total tasks: 1\n", "", False, 8)
            with mock.patch.dict(
                os.environ,
                {
                    "SWE_RUNNER_CONFIG": str(swe_config),
                    "NODES_CONFIG": str(nodes_config),
                    "TEST_NODE_PASSWORD": "secret-value",
                },
            ), mock.patch(
                "dingtalk_ops_bridge.actions.run_process", return_value=process
            ) as run_process:
                execution = execute_actions(
                    action_catalog,
                    ("swe-status",),
                    {},
                    context=ActionContext(),
                )
            self.assertTrue(execution.results[0].ok)
            command = run_process.call_args.args[0]
            self.assertIn("ops@10.0.0.70", command)
            self.assertEqual(run_process.call_args.kwargs["env"]["SSHPASS"], "secret-value")

            with mock.patch.dict(
                os.environ,
                {
                    "SWE_RUNNER_CONFIG": str(swe_config),
                    "NODES_CONFIG": str(nodes_config),
                    "TEST_NODE_PASSWORD": "secret-value",
                },
            ), mock.patch.object(
                self.plugin, "_run_process", return_value=self.plugin._ProcessResult(0, "Total tasks: 1\n", "", False, 8)
            ) as plugin_run_process:
                output = handle_prompt("69 status", action_catalog)
            self.assertIn("swe-runner status - 69", output)
            self.assertIn("ops@10.0.0.70", plugin_run_process.call_args.args[0])

    def test_help_lists_plugin_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = load_action_catalog(self._write_actions(root), registry=self.registry)
        output = format_help(catalog)
        self.assertIn("**插件命令**", output)
        self.assertIn("`swe-runner status|query|s|q`", output)
        self.assertIn("**插件帮助**", output)
        self.assertIn("`help swe-runner`", output)
        self.assertIn("`swe-runner help`", output)
        self.assertIn("- `status`：立即执行全部已启用监控", output)

    def test_help_routes_swe_runner_topics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            swe_config = self._write_config(root)
            catalog = load_action_catalog(self._write_actions(root), registry=self.registry)
            with mock.patch.dict(os.environ, {"SWE_RUNNER_CONFIG": str(swe_config)}):
                status_help = handle_prompt("help swe-runner status", catalog)
                target_help = handle_prompt("help swe-runner 69", catalog)
                plugin_help = handle_prompt("swe-runner help status", catalog)
        self.assertIn("swe-runner status", status_help)
        self.assertIn("swe-runner 目标：69", target_help)
        self.assertIn("swe-runner status", plugin_help)

    def _write_config(self, root: Path) -> Path:
        path = root / "swe-runner.json"
        path.write_text(
            json.dumps(
                {
                    "default": "69",
                    "targets": {
                        "69": {
                            "aliases": ["10.0.10.69"],
                            "host": "10.0.10.69",
                            "queue": "queue-69",
                            "user": "test",
                            "remoteDir": "/opt/swe-runner",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        return path

    def _write_actions(self, root: Path) -> Path:
        path = root / "actions.json"
        path.write_text(
            json.dumps({"actions": {"hello": {"command": ["true"]}}}),
            encoding="utf-8",
        )
        return path

    def _write_monitors(self, root: Path) -> Path:
        path = root / "monitors.json"
        path.write_text(
            json.dumps(
                {
                    "monitors": {
                        "ok-check": {
                            "check": {"type": "command", "command": ["true"]},
                            "enabled": True,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        return path


if __name__ == "__main__":
    unittest.main()
