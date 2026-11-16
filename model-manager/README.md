# model-manager Plugin

该插件管理 vLLM 等模型实例的节点、日志和监控定义，也提供通用的节点服务健康监控。监控定义随插件分发，不再写入框架的 `config/monitors.json`。

## 结构

```text
plugins/model-manager/
  action_plugin.json
  config/models.json
  config/models.example.json
  src/model_manager_plugin/__init__.py
  src/model_manager_plugin/alerts.py
  src/model_manager_plugin/model_state.py
  src/model_manager_plugin/service_state.py
  tests/test_model_manager.py
```

manifest 同时注册 `model-log`、`node-service` monitor provider、`model` 命令和 `models` 服务，并通过 `requires: ["nodes"]` 复用节点登录信息。

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
      "alertPatterns": [
        "No available shared memory broadcast",
        "Shutting down"
      ],
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

同一文件可用 `services` 声明节点服务监控。每项至少配置 `container` 或 `url`：

```json
{
  "services": {
    "newapi-205": {
      "description": "205 new-api 容器与 API 健康检查",
      "node": "hangdian2-205",
      "container": "new-api",
      "url": "http://127.0.0.1:3000/api/status",
      "expectedStatus": 200,
      "monitorName": "newapi-status-205",
      "intervalSeconds": 60,
      "timeoutSeconds": 20,
      "urlTimeoutSeconds": 5,
      "severity": "critical",
      "notifyRecovery": true,
      "enabled": true
    }
  }
}
```

`node-service` 会在目标节点上检查 Docker 容器是否运行，并通过本机地址请求 HTTP 状态。默认监控名为 `model-manager-<服务名>-service`。

## 命令

```text
model list
model check vllm-27
model check vllm-27,vllm-31
model add name=vllm-32 node=hangdian2-32 logPath=/data/applogs/vllm.log alertPatterns='Shutting down'
help model add
help alert add model-log
model help check
alert list
alert disable vllm-shared-memory-27
alert remove newapi-status-205
alert add name=extra-vllm type=model-log model=vllm-31 intervalSeconds=30
service list
service add name=redis-205 node=hangdian2-205 container=redis intervalSeconds=30
service update name=newapi-205 expectedStatus=204 intervalSeconds=120
service remove newapi-205
service restore newapi-205
service check newapi-205
monitor check newapi-status-205
models
模型
```

`model list` 显示模型和服务监控配置。`model check` 立即读取最近 `tailLines` 行，命中任一
`alertPatterns` 时返回异常；服务监控可用 `service check <服务名>` 或
`monitor check <监控名>` 立即执行。`help model`、`help alert` 和 `help service`
由框架统一路由到插件，不需要在框架中维护参数字段。

## 动态添加模型

运行时可通过钉钉添加模型，不修改只读的插件配置文件：

```text
model add name=vllm-32 node=hangdian2-32 logPath=/data/applogs/vllm.log alertPatterns='Shutting down,No available shared memory broadcast'
```

必填参数为 `name`、`node`、`logPath` 和 `alertPatterns`。可选参数包括
`description`、`monitorName`、`tailLines`、`intervalSeconds`、`timeoutSeconds`、
`severity`、`repeatAlertSeconds`、`notifyRecovery` 和 `enabled`。多个关键字用逗号分隔，
也可传 JSON 数组。模型名和监控名必须唯一，`node` 必须存在，`logPath` 必须是绝对路径。

动态模型默认写入 `DATA_DIR/model-manager-models.json`，文件权限为 `0600`，可用
`MODEL_MANAGER_MODEL_STATE_FILE` 覆盖路径。`model list` 会将来源标为“动态添加”，
`model check` 可立即验证；`bridge` 无需重启。新增监控要由后台进程加载，因此执行：

```bash
docker compose restart monitor
```

## 动态管理服务

服务可通过钉钉动态添加、修改、移出和恢复，无需修改只读的 `config/models.json`：

```text
service add name=redis-205 node=hangdian2-205 container=redis intervalSeconds=30
service add name=newapi-probe node=hangdian2-205 url=http://127.0.0.1:3000/health expectedStatus=200
service update name=newapi-205 expectedStatus=204 intervalSeconds=120
service update name=redis-205 url=http://127.0.0.1:6379/health
service remove newapi-205
service restore newapi-205
service list
service check newapi-205
```

`service add` 必填 `name`、`node`，以及 `container` 或 `url` 至少一项。可选参数包括
`description`、`monitorName`、`expectedStatus`、`urlTimeoutSeconds`、`intervalSeconds`、
`timeoutSeconds`、`severity`、`repeatAlertSeconds`、`notifyRecovery` 和 `enabled`。
`service update` 只修改指定字段并保留其余配置，也可覆盖 `config/models.json` 中的静态服务。
`service remove` 不删除定义，`service restore` 可恢复。

动态服务默认写入 `DATA_DIR/model-manager-services.json`，文件权限为 `0600`，可用
`MODEL_MANAGER_SERVICE_STATE_FILE` 覆盖路径。`service list` 会标记 `动态添加`、
`动态覆盖` 和 `已移出`。新增、更新或恢复后执行 `docker compose restart monitor`
加载周期监控；`service check` 和 `alert add type=node-service` 可立即使用新定义。

## 告警管理

告警项的关闭、移出和添加由 model-manager 插件管理，不修改固定框架镜像。状态默认写入
`DATA_DIR/model-manager-alert-management.json`，可用
`MODEL_MANAGER_ALERT_STATE_FILE` 覆盖路径。

```text
alert list
alert help
alert help model-log
alert help http
alert disable vllm-shared-memory-27,newapi-status-205
alert enable vllm-shared-memory-27,newapi-status-205
alert remove newapi-status-205
alert restore newapi-status-205
alert add name=extra-vllm type=model-log model=vllm-31 intervalSeconds=30 severity=warning
alert add name=extra-service type=node-service service=newapi-205
alert add name=api-health type=http url=http://127.0.0.1:8080/health expectedStatus=200
alert add name=redis-port type=tcp host=10.0.0.12 port=6379
alert add name=host-ready type=command command='hostname' stdoutContains=worker
```

`disable` 保留定义但关闭调度；`remove` 将告警移出；`restore` 恢复已移出项。
`add` 支持 `model-log`、`node-service`、`http`、`tcp` 和 `command`。新增或移出后，
重启 `monitor` 容器使框架重新读取插件的监控定义：

`alert help <类型>` 显示该类型的必填参数和示例。`model-log` 中的 `model` 指
`config/models.json` 里 `models` 下的实例键（例如 `vllm-31`），它关联节点、日志路径和
异常关键字，不是底层模型权重名称。`node-service` 中的 `service` 同理，指向 `services`
下的服务实例键。

```bash
docker compose restart monitor
```

这是固定框架仅提供启动时 monitor provider 加载接口造成的限制；桥接容器无需重启。

## 监控

框架加载监控时调用插件的 `monitors(context)`，为每个模型生成 `model-log` 监控项，为每个服务生成 `node-service` 监控项。后台 monitor 进程发现异常或恢复后，仍由框架统一发送钉钉 Webhook。

修改静态模型、节点、日志或关键字后，重启服务：

```bash
docker compose restart bridge monitor
```

通过 `model add` 添加的模型已持久化到 `DATA_DIR`，只重启 `monitor` 即可开始周期告警。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s plugins/model-manager/tests -v
PYTHONPATH=src python3 -m dingtalk_ops_bridge validate
PYTHONPATH=src python3 -m dingtalk_ops_bridge command 'model list'
PYTHONPATH=src python3 -m dingtalk_ops_bridge command 'service list'
```
