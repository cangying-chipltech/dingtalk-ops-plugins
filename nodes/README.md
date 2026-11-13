# nodes Plugin

该插件把节点清单、SSH 登录动作和 `nodes` 命令做成外部插件，框架镜像不包含节点实现。

## 结构

```text
plugins/nodes/
  action_plugin.json
  config/actions.json
  config/nodes.json
  config/nodes.example.json
  src/nodes_plugin/__init__.py
```

插件同时注册 `node` 动作类型、`nodes` 命令 provider，并通过 `config/actions.json`
提供 `node-login`、`node-info`、`node-disk` 和 `node-health`。

命令 provider 通过 `command_prefixes = ("node", "nodes", "节点")` 声明确定性路由。

manifest 还通过 `services: {"nodes": "SERVICE"}` 暴露节点服务，供 swe-runner 等插件
复用。服务提供 `list_nodes(context)`、`resolve(name, context)` 和
`ssh_command(name, remote_command, context)`，不会向调用方返回密码。

## 配置

默认读取 `config/nodes.json`，也可以用 `NODES_CONFIG` 指向其他文件。旧环境变量
`NODES_FILE` 仍兼容。示例见 `config/nodes.example.json`。

```json
{
  "nodes": {
    "web-01": {
      "host": "10.0.0.11",
      "port": 22,
      "user": "ops",
      "passwordFile": "../../../data/secrets/web-01.password"
    }
  }
}
```

支持 `passwordEnv`、`passwordFile` 或 `identityFile` 认证，禁止直接配置
`password`、`passphrase` 或 `secret`。`passwordEnv` 和 `passwordFile` 只能二选一。

`passwordEnv` 从容器环境变量读取密码：

```text
NODE_WEB01_SSH_PASSWORD=<password>
```

`passwordFile` 使用 `sshpass -f` 在每次 SSH 执行时读取文件，因此轮换密码只需原子替换
文件，不需要重启服务：

```bash
install -d -m 700 data/secrets
printf '%s\n' '<new-password>' > data/secrets/web-01.password.tmp
chmod 600 data/secrets/web-01.password.tmp
mv data/secrets/web-01.password.tmp data/secrets/web-01.password
```

密码文件路径相对 `nodes.json`；容器内推荐放在 `/app/data/secrets/`。不要把密码文件放进
镜像或提交到 Git。首次启用 `passwordFile` 需要更新并重启一次插件，此后改密码无需重启。

相对路径以节点配置文件所在目录为基准。容器内推荐使用 `/app/data/ssh/` 和
`/app/data/known_hosts`。

## 命令

```text
nodes
node list
节点
```

命令只显示节点名称、主机、用户、端口和认证方式，不显示密码变量值。

## 动作

插件自带 `config/actions.json`，通过 `actionsFile` 自动合并到框架动作列表。可以继续
添加同类型动作：

```json
{
  "actions": {
    "node-login": {
      "type": "node",
      "remoteCommand": "hostname",
      "timeoutSeconds": 20,
      "parameters": {
        "node": {"type": "node", "required": true}
      }
    }
  }
}
```

执行方式：`run node-login node=web-01`。

## 验证

```bash
PYTHONPATH=src python3 -m dingtalk_ops_bridge validate
PYTHONPATH=src ./scripts/agent-router.sh nodes
PYTHONPATH=src python3 -m unittest discover -s plugins/nodes/tests -v
```
