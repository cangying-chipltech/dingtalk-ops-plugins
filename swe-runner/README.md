# swe-runner Plugin

该插件把旧 bridge 的 swe-runner 查询做成外部 action/command 插件，框架镜像无需修改。

## 结构

```text
plugins/swe-runner/
  action_plugin.json
  config/swe-runner.json
  src/swe_runner_plugin/__init__.py
```

`action_plugin.json` 同时声明 `provider` 和 `commandProvider`。框架启动时自动导入插件，
注册 `swe-runner` 动作类型和兼容命令。manifest 中的 `requires: ["nodes"]` 表示它依赖
nodes 插件提供的 `nodes` 服务；加载器会保证 nodes 先加载。

命令 provider 声明 `status`、`query`、`history`、`recent`、`swe-runner` 等固定前缀，
并注册唯一 fallback 以兼容 `69 status` 这类目标名动态命令。裸 `check` 被框架保留。

## 配置

默认读取 `config/swe-runner.json`，也可用 `SWE_RUNNER_CONFIG` 覆盖。推荐目标通过
`node` 引用 nodes 插件中的节点，由节点插件统一管理连接信息：

```json
{
  "default": "69",
  "targets": {
    "69": {
      "node": "worker-01",
      "queue": "10.0.10.69",
      "aliases": ["69"],
      "remoteDir": "/mnt/jfs/tools/swe-runner"
    }
  }
}
```

旧格式的 `host`、`user`、`passwordEnv`、`port` 和 `strictHostKeyChecking` 仍兼容，
但使用 `node` 时不能再写这些字段。示例见 `config/swe-runner.example.json`。

使用 `node` 时，SSH 密码由 nodes 插件配置中的 `passwordEnv` 提供；使用旧的内联
`host`/`user` 配置时，密码变量写在 swe-runner 目标中。密码都由 `sshpass -e` 传入，
不会出现在命令行或回复中。示例环境变量：

```text
NODE_WORKER01_SSH_PASSWORD=<password>
SWE_RUNNER_KNOWN_HOSTS=/app/data/known_hosts
```

`SWE_RUNNER_KNOWN_HOSTS` 只用于旧的内联目标；节点目标使用 nodes 插件的 known_hosts
配置。启用密码认证需要镜像中的 `sshpass` 和 `openssh-client`，框架镜像已包含。

## 命令

```text
swe-runner status
swe-runner history
swe-runner 69 status
swe-runner 10.0.10.69 history
swe-runner query
swe-runner recent
69 status
10.0.10.69 history
swe-runner help
swe-runner help status
swe-runner help 69
help swe-runner status
```

插件命令应带 `swe-runner` 前缀；裸 `status`、`check` 始终由框架执行监控检查。若插件
显式声明并占用裸 `status`，可使用 `bridge status` 调用框架监控。`69 status` 等目标优先
写法仅作为旧 bridge 兼容。未配置默认目标时，插件命令会返回配置错误。

## 动作

在 `config/actions.json` 中引用插件类型：

```json
{
  "swe-status": {
    "type": "swe-runner",
    "description": "查询 swe-runner 状态",
    "target": "69",
    "history": false
  }
}
```

执行 `run swe-status`，或传入 `target=69` 覆盖默认目标。远程命令为
`cd <remoteDir> && ./status_swebench.sh <queue> --verbose [--history]`。

## 验证

```bash
PYTHONPATH=src python3 -m dingtalk_ops_bridge validate
PYTHONPATH=src ./scripts/agent-router.sh help
PYTHONPATH=src python3 -m unittest discover -s plugins/swe-runner/tests -v
```
