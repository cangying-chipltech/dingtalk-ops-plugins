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
        self.nodes = FakeNodes()
        self.context = ActionContext(services={"nodes": self.nodes})
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
                    }
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
