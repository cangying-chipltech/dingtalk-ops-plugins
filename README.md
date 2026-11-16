# DingTalk Ops Plugins

该仓库存放 `dingtalk-ops-bridge` 固定镜像挂载的 action、command 和 monitor 插件。

## 插件

- `nodes/`：节点清单、SSH 动作和 `nodes` 服务。
- `model-manager/`：模型清单、`model-log` 监控、`model` 命令和 `alert` 告警管理。
- `swe-runner/`：swe-runner 查询动作与旧命令兼容。

## 部署

在主框架仓库根目录执行：

```bash
git clone git@github.com:cangying-chipltech/dingtalk-ops-plugins.git plugins
docker compose restart bridge monitor
```

Compose 将 `./plugins` 只读挂载到 `/app/plugins`。

## 本地配置

节点、swe-runner 目标和模型实例配置是环境私有文件，已被 `.gitignore` 排除：

```text
nodes/config/nodes.json
swe-runner/config/swe-runner.json
model-manager/config/models.json
```

从对应的 `.example.json` 创建。密码和 Webhook 凭据继续由主框架的 `.env` 或
`data/secrets/` 管理，不写入本仓库。

## 验证

```bash
cd plugins
PYTHONPATH=../src python3 -m unittest discover -s nodes/tests -v
PYTHONPATH=../src python3 -m unittest discover -s model-manager/tests -v
PYTHONPATH=../src python3 -m unittest discover -s swe-runner/tests -v
```
