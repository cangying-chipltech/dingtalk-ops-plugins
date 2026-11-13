# model-manager Plugin

该插件管理 vLLM 等模型实例的节点、日志和监控定义。模型日志监控随插件分发，不再写入框架的 `config/monitors.json`。

## 结构

```text
plugins/model-manager/
  action_plugin.json
  config/models.json
  config/models.example.json
  src/model_manager_plugin/__init__.py
  tests/test_model_manager.py
```

manifest 同时注册 `model-log` monitor provider、`model` 命令和 `models` 服务，并通过 `requires: ["nodes"]` 复用节点登录信息。

## 配置

默认读取 `config/models.json`，可用 `MODEL_MANAGER_CONFIG` 覆盖。参考 `config/models.example.json`：

```json
{
  "models": {
    "vllm-27": {
      "description": "27 节点 vLLM 日志监控",
      "node": "hangdian2-27",
      "logPath": "/data/applogs/vllm.log",
      "tailLines": 10,
      "alertPatterns": ["No available shared memory broadcast"],
      "monitorName": "vllm-shared-memory-27",
      "intervalSeconds": 60,
      "timeoutSeconds": 20,
      "severity": "critical",
      "repeatAlertSeconds": 0,
      "notifyRecovery": true,
      "enabled": true
    }
  }
}
```

`node` 必须引用 nodes 插件中的节点。插件会通过 nodes 服务的 SSH 配置读取日志，不在模型配置中保存密码。`monitorName` 可选，默认使用 `model-manager-<模型名>-log`。

## 命令

```text
model list
model check vllm-27
model check vllm-27,vllm-31
models
模型
```

`model list` 显示模型、节点、日志、关键字和监控项名称。`model check` 立即读取最近 `tailLines` 行，命中任一 `alertPatterns` 时返回异常。

## 监控

框架加载监控时调用插件的 `monitors(context)`，为每个模型生成一个 `model-log` 监控项。后台 monitor 进程发现异常或恢复后，仍由框架统一发送钉钉 Webhook。

修改模型、节点、日志或关键字后，只需重启服务：

```bash
docker compose restart bridge monitor
```

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s plugins/model-manager/tests -v
PYTHONPATH=src python3 -m dingtalk_ops_bridge validate
PYTHONPATH=src python3 -m dingtalk_ops_bridge command 'model list'
```
