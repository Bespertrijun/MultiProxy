# 发布清单：多副本故障转移功能

本文档为上线"多副本故障转移"功能（Phase 4a）的运维清单。

## 上线前（Pre-launch）

### 1. 备份生产数据

上线前对现有 SQLite 数据库做快照备份，以便故障时快速恢复：

```bash
# 在面板宿主机上
# 假设数据目录是 /opt/multiproxy/
cp /opt/multiproxy/panel.db /opt/multiproxy/panel.db.backup.$(date +%Y%m%d_%H%M%S)

# 验证备份
ls -lh /opt/multiproxy/panel.db.backup.*
```

建议保留至少 3 个最近的备份，以应对数据损坏或意外变更。

### 2. 准备 Kill-Switch 环境变量

在面板启动脚本或 systemd 服务中，确保 kill-switch **默认关闭**（正常上线）：

```bash
# /etc/systemd/system/multiproxy-panel.service 中
# 不设置或设置为 0（默认关闭故障转移）
Environment="PANEL_FAILOVER_KILLSWITCH=0"

# 若需要应急模式启动，改为：
# Environment="PANEL_FAILOVER_KILLSWITCH=1"
```

重启 systemd，使环境变量生效：

```bash
systemctl daemon-reload
```

### 3. 验证 Agent 版本

确保现网所有 agent 已升级到支持多副本的版本（v0.x.y 及之后）。检查各节点：

```bash
# SSH 到各 NAT 节点
agent --version

# 或检查面板侧的概览
curl -s -b cookies.txt http://panel.example.com:8080/api/health | jq '.nodes[] | {id, agent_version}'
```

### 4. 本地测试

在开发环境或灰度环境测试整个故障转移流程：

```bash
# 构建并启动本地面板 + agent
cargo build -p panel -p agent --release

# 在面板中创建规则并添加副本后端
# 观察 StatusReport 中的 active_backends 变化
# 模拟主后端故障（iptables drop / 停服务），验证切换行为
# 验证 kill-switch API 功能正常
```

## 上线中（During launch）

### 1. 升级面板二进制

根据项目的发版流程，更新面板到新版本：

```bash
# 若使用一键脚本
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-panel.sh | \
  bash -s -- --admin-pass "your-password"

# 或通过 Web UI 自更新
# 进入面板 → 系统设置 → 系统更新 → 检查更新 → 更新面板
```

### 2. 升级 Agent 二进制

在每个 NAT 节点升级 agent（通常通过重新运行安装脚本）：

```bash
# 在 NAT 节点上
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-agent.sh | \
  bash -s -- --panel-url wss://panel.example.com/agent \
               --node-id <NODE_ID> --token <TOKEN>
```

或使用 agent 自更新：

```bash
agent --self-update --panel-url wss://panel.example.com/agent
```

### 3. 监控 Kill-Switch 可达性

确保 kill-switch API 在上线过程中始终可达：

```bash
# 定期检查
curl -s -b cookies.txt http://panel.example.com:8080/api/settings/failover-killswitch
```

记录结果，若 API 不可达立即告警。

### 4. 逐步启用多副本规则

建议**分阶段**推出：

**阶段 1：灰度** — 仅在非关键节点上配置多副本规则，观察 48 小时。

**阶段 2：扩大** — 在更多关键节点上配置多副本，继续观察。

**阶段 3：全量** — 所有规则都支持多副本。

在每个阶段间隔观察 agent 日志、StatusReport、DNS 解析结果、客户端连接，确认无异常。

## 上线后（Post-launch）

### 1. 监控指标

持续监控以下指标：

- **Agent 连接状态**：所有节点应保持 `online`。
  ```bash
  curl -s -b cookies.txt http://panel.example.com:8080/api/health | jq '.nodes[] | {id, status}'
  ```

- **后端健康状态**：在面板**概览**中查看每个规则的 `backend_health`，确保探测正常。

- **活跃副本分布**：观察 `active_backends`，确认故障转移按预期进行。
  ```bash
  curl -s -b cookies.txt http://panel.example.com:8080/api/health | \
    jq '.nodes[] | {id, reports: .reports[0].active_backends}' 
  ```

- **客户端错误率**：监控 Emby 客户端或用户端的连接错误、超时、重连频率。预期应无显著增加。

### 2. 日志检查

定期查看面板和 agent 日志，检查异常：

**面板日志**：
```bash
journalctl -u multiproxy-panel -f
# 或检查容器日志
docker logs -f multiproxy-panel
```

关键日志行：
- `failover kill-switch toggled`：kill-switch 状态变化。
- `config gen bump`：配置下发。
- `agent connected` / `agent disconnected`：节点连接状态。

**Agent 日志**：
```bash
# SSH 到 NAT 节点
journalctl -u multiproxy-agent -f
```

关键日志行：
- `probe result`：探测结果。
- `switch active backend`：副本切换。
- `re-render config`：配置重新渲染（通常伴随重启）。

### 3. 故障转移场景验证

在非高峰期进行**受控故障测试**：

**场景 1：主后端故障**
- 停止主后端服务 / 配置 iptables DROP 规则。
- 观察 agent 日志，确认约 15 秒后切到备用。
- 观察面板**概览**，`active_backends` 应指向备用。
- 确认 Emby 客户端可恢复连接（可能需要重连）。

**场景 2：主后端恢复**
- 恢复主后端服务。
- 观察 agent 日志，约 30 秒后应标记主为 UP，但因最小驻留 60 秒，还不会切回。
- 等待 ~60 秒后，观察 `active_backends` 切回主。
- 确认连接流畅，无瞬时中断。

**场景 3：Kill-Switch 启用**
- 通过 API 启用 kill-switch。
- 观察 agent 日志，应显示 `received legacy single-upstream config`。
- 验证该配置下降级为单主上游（`extra_backends` 被忽略）。
- 禁用 kill-switch，观察恢复到多副本配置。

### 4. 异常处理

若上线过程中发现异常：

| 异常现象 | 可能原因 | 应对 |
|--------|--------|------|
| Agent 频繁重连 | 配置下发 / 网络抖动 | 检查面板日志、网络连接，考虑增加 `min_dwell_secs` |
| 客户端频繁断连 | 故障转移过于频繁 | 启用 kill-switch，调整超时/重试参数 |
| 某规则无法探测后端 | 网络策略 / 防火墙 | 检查节点到后端的网络连通性，放开必要端口 |
| Panel API 响应缓慢 | 数据库锁竞争 | 检查 SQLite，可考虑迁移到 PostgreSQL（未来增强）|

**紧急回滚步骤**：

```bash
# 1. 启用 kill-switch（秒级生效）
curl -s -b cookies.txt -X PUT -H 'Content-Type: application/json' \
  -d '{"enabled":true}' http://panel.example.com:8080/api/settings/failover-killswitch

# 2. 观察（给 agent 足够时间接收新配置，最多 5 分钟）
sleep 60
curl -s -b cookies.txt http://panel.example.com:8080/api/health | jq '.nodes[] | {id, status}'

# 3. 若仍有问题，重启面板（会恢复到启动时的 env var 设置）
systemctl restart multiproxy-panel
```

### 5. 客户端通知

若因为故障转移导致了用户端连接中断，及时通知用户：

- **通知内容**：系统进行了故障转移维护，若 Emby 客户端显示连接错误，请重新启动应用或切换网络再试。
- **通知时机**：上线前（预公告）+ 上线中（进行中）+ 上线后（完成通知）。

### 6. 数据验证

上线完成后，验证数据完整性：

```bash
# 检查规则是否正确保存 extra_backends
sqlite3 /opt/multiproxy/panel.db \
  "SELECT id, backend_host, backend_port, extra_backends FROM forward_rule LIMIT 5;"

# 验证各节点的 StatusReport 已持久化
curl -s -b cookies.txt http://panel.example.com:8080/api/health | \
  jq '.nodes[] | {id, last_report_at, active_backends}' | head -20
```

## 常见问题

### Q1：为什么启用多副本后，某规则的所有客户端都被断开了？

**A**：当 agent 探测发现活跃副本变化时，会重新渲染配置并重启 relay 进程。这会导致该工具（gost/realm）管理的所有规则的现有连接中断。这是设计决策，通过**非对称的快失败/慢恢复** + **最小驻留**来把断开频率降到罕见。

### Q2：主后端恢复后为什么不立即切回？

**A**：通过 `min_dwell_secs`（默认 60 秒）最小驻留机制，防止瞬时抖动（主短暂故障后快速恢复）导致频繁切换。这是为了稳定性而设计的。若确实需要更快速地切回，可在面板**系统设置**中调整 `min_dwell_secs` 为更小的值（如 10 秒）。

### Q3：如何在线迁移两条规则为一条多副本规则？

**A**：见上方"运维：现网多规则合并"小节。操作步骤是：编辑保留规则 → 添加副本 → 验证 → 删除旧规则。客户端会在旧规则删除时断连。

### Q4：Kill-Switch 启用后，为什么 agent 还在报告多副本？

**A**：Kill-Switch 只影响**面板下发的配置**（推送单主）。Agent 端若已收到新配置并应用，则不再运行故障转移引擎。若仍看到多副本，说明 agent 还没收到新配置，等待下一次心跳/推送（最多 5 分钟）或手动推送。

## 附录：重要参数速查

| 参数 | 默认值 | 作用 | 调整场景 |
|-----|-------|------|--------|
| `probe_interval_secs` | 5 | 探测周期 | 若网络延迟高，增大以减少假失败 |
| `failover_max_fails` | 3 | 判定故障的失败次数 | 若主频繁抖动，增大(如5)以容忍短暂抖动 |
| `failover_recovery_checks` | 6 | 判定恢复的成功次数 | 同上 |
| `min_dwell_secs` | 60 | 最小驻留时间 | 若切换过于频繁，增大；若需要快速恢复，减小 |
| `PANEL_FAILOVER_KILLSWITCH` | 0 | Kill-Switch 默认值 | 应急时设为 1；上线前确保为 0 |

## 参考文档

- 功能设计文档：[`.omc/specs/deep-interview-multi-backend-failover.md`]
- Agent 代码：[`crates/agent/src/failover.rs`]
- 协议定义：[`crates/contract/src/protocol.rs`] 中的 `BackendHealth` / `ActiveBackend`
- 主 README：[`README.zh-CN.md`](../README.zh-CN.md) / [`README.md`](../README.md)
