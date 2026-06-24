# multiProxy — Emby 多前置 NAT 中转 + GeoDNS 分线路

![CI](https://github.com/Bespertrijun/MultiProxy/actions/workflows/ci.yml/badge.svg)

[English](README.md) | 简体中文

multiProxy 用一批分布在不同**运营商/地区**的 **NAT 中转节点**为单一后端（例如 **Emby** 媒体服务器）做前置，并通过**自建 GeoDNS**——按客户端的地区/运营商线路返回不同解析结果——把每个用户导向最合适的前置节点。一个中心**面板（panel）**管理整个节点群、渲染每个节点的转发配置、跟踪节点健康与容量、并对外提供 DNS 解析；每个 NAT 节点上的轻量 **agent** 主动反连面板、应用下发的配置、监管本地转发工具（gost/realm）、并定期上报自身状态。

> 状态：M0 + M1 已完成并通过验证；M3 的部署/文档产物与一次真实的跨二进制集成冒烟在 `deploy/`。请看文末的验收标准状态与「需要真实环境 / 已推迟」清单——本仓库不声称已部署或已在生产验证。

---

## 为什么需要它

外部 DNS 服务商（Cloudflare、DNSPod……）无法按**中国大陆运营商线路**返回不同解析。multiProxy 为解析域名保留一台**自托管权威 GeoDNS**，用 **EDNS Client Subnet (ECS)**——ECS 缺失时退化为递归器源 IP——对客户端做地理/运营商定位，返回命中该线路的前置节点。终端用户把 Emby 客户端指向该解析域名即可；他们会连上一台前置节点，由它 NAT/中转到真正的后端。

---

## 架构

```
                 ┌──────────────── 面板宿主机（非 NAT，公网 IP，:53）──────────────┐
   终端用户       │   ┌─────────────┐        ┌──────────────────────────────────────┐ │
 (Emby 客户端)   │   │  GeoDNS     │  读取  │  panel (axum)                         │ │
       │  dig    │   │ (hickory,   │◄───────┤  • CRUD：节点 / 规则 / 区域 /         │ │
       ├────────►│   │  :53 udp/tcp│ 快照   │    线路组 + 鉴权（会话）              │ │
       │  A 记录 │   │  独立 runtime│       │  • 配置渲染（gost/realm）             │ │
       │◄────────┤   │             │        │  • WS 反连服务端  /agent              │ │
       │         │   └─────────────┘        │  • 健康 + 容量调度器                  │ │
       │         │                          │  • SQLite（内置 libsqlite3）          │ │
       │         └──────────────────────────┴──────────────────────────────────────┘ │
       │                                            ▲  wss:// 反向连接                 │
       │                                            │  Hello/HelloOk/ConfigPush/Ack    │
       │                                            │  Heartbeat/StatusReport          │
  ┌────┴──────── 前置 NAT 节点 ───────────┐         │                                  │
  │  agent（静态 musl）                   ├─────────┘                                  │
  │   • 应用 ConfigPush → 写配置文件      │                                            │
  │   • 监管 gost/realm 子进程            │   中转                                      │
  │   • 探测后端、上报容量                ├──────────────►  Emby 后端                  │
  └───────────────────────────────────────┘                                           │
```

### 两个 DNS 角色（切勿混为一谈）

1. **解析域名 ①**（如 `emby.example.com`）—— 由**内嵌 GeoDNS** 解析，负责地区/运营商分流。在 Cloudflare 里用 NS 记录（灰云/不代理）委派给 GeoDNS 宿主机。终端用户把 Emby 指向这里。
2. **面板控制域名 ②**（如 `panel.example.com`）—— 保留在**稳定的外部服务商**（CF/DNSPod）上，**不**走内嵌 GeoDNS，这样即便面板/GeoDNS 故障，agent 仍能解析到面板地址来重连；该域名同时用于 ② 的 DNS-01 ACME 证书签发。

完整操作手册：[`deploy/dns-setup.md`](deploy/dns-setup.md)。

---

## Crate 结构

Cargo workspace（`Cargo.toml`），四个 crate：

| Crate              | 职责 |
|--------------------|------|
| `crates/contract`  | 与传输无关的线协议（JSON 信封：Hello / HelloOk / ConfigPush / ConfigAck / Heartbeat / StatusReport / AuthReject / Close）、数据模型、ISP/区域类型、协议版本。刻意只依赖 serde，以保持 agent 的 musl 体积纤薄。**勿轻易改动其语义。** |
| `crates/geoip`     | `GeoIpProvider` trait 背后的 IP→(区域, 运营商) 查询；GeoCN MMDB provider + 可热重载的 `ProviderHandle`（ArcSwap）；一个格式切换 stub。ipip/纯真 适配器推迟。 |
| `crates/panel`     | 管理面：CRUD + 鉴权、gost/realm 配置渲染、WS 反连服务端、健康/容量调度器，以及在独立 runtime 上的进程内 GeoDNS（hickory）。SQLite 经 sqlx + 内置 libsqlite3。 |
| `crates/agent`     | 每节点的轻量静态 agent：带退避的 wss 反连、配置应用、gost/realm 进程监管 + 自愈、容量遥测。双架构 musl，rustls + ring。 |

---

## 构建

标准 workspace 构建（宿主架构）：

```sh
cargo build --workspace            # debug
cargo build --release --workspace  # release（panel + agent + 库）
```

### 双架构静态 musl agent

agent 以完全静态、零运行时依赖的二进制按架构发布。用 `cargo-zigbuild` 交叉构建两种架构（无需原生 ARM 硬件）：

```sh
cargo zigbuild -p agent --release --target x86_64-unknown-linux-musl
cargo zigbuild -p agent --release --target aarch64-unknown-linux-musl
```

工具链准备、验证（`file` / `ldd`）与多架构容器 manifest 见 [`crates/agent/BUILD.md`](crates/agent/BUILD.md)。

---

## 快速部署（一键脚本,无需编译）

从 [GitHub Releases](https://github.com/Bespertrijun/MultiProxy/releases) 下载预编译二进制,一行命令完成安装。

### 安装面板（主控机）

```sh
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-panel.sh | bash -s -- \
  --admin-pass "你的强密码"
```

脚本自动完成:下载面板二进制 → 初始化数据库和管理员 → 下载 GeoCN IP 库 → 安装 systemd 服务并启动。

可选参数:
| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--admin-pass` | (必填) | 管理员密码 |
| `--dns-port` | `53` | GeoDNS 端口 |
| `--http` | `0.0.0.0:8080` | Web 绑定 |
| `--data-dir` | `/opt/multiproxy` | 数据目录 |
| `--no-geocn` | - | 跳过下载 IP 库 |
| `--no-systemd` | - | 不装 systemd 服务 |

### 安装 Agent（每台 NAT 小鸡）

在面板中添加节点后,复制显示的一键安装命令,到 NAT 小鸡上执行:

```sh
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-agent.sh | bash -s -- \
  --panel-url wss://panel.example.com/agent \
  --node-id <节点ID> --token <节点Token>
```

脚本自动完成:检测架构(x86_64/aarch64) → 下载对应 agent 二进制 → 下载 gost → 安装 systemd 服务并启动。

### 完整部署流程

```
1. 主控机运行面板安装脚本
2. 打开面板 → 系统设置 → 配置 Cloudflare（自动搞定 DNS）
3. 添加 DNS 域名（如 emby.example.com）
4. 添加节点 → 复制安装命令
5. NAT 小鸡上粘贴运行安装命令
6. 回面板 → 添加转发规则 → 配线路组
7. 用户在 Emby 客户端填域名即可使用
```

### 更新

面板支持在线自更新:

- **面板更新**: 系统设置 → 检查更新 → 一键更新（自动下载新版 + 重启）
- **Agent 更新**: `agent --self-update --panel-url wss://...` 或重新运行安装脚本
- **发版**: `git tag v0.2.0 && git push --tags` → CI 自动构建发布到 GitHub Releases

---

## 本地开发运行（高位 DNS 端口，无需特权）

从源码运行(开发用):

```sh
# 1. 一次性：创建管理员用户
cargo run -p panel -- init --admin-pass "change-me"

# 2. 启动面板（DNS 用高位端口免去特权绑定）
cargo run -p panel -- serve \
  --db "sqlite://panel.db" \
  --http "127.0.0.1:8080" \
  --dns-addr "127.0.0.1" \
  --dns-port 15353
```

验证:

```sh
# 登录
curl -c cj.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}' http://127.0.0.1:8080/api/login
# 创建节点
curl -b cj.txt -H 'Content-Type: application/json' \
  -d '{"name":"n1","public_ip":"203.0.113.7"}' http://127.0.0.1:8080/api/nodes
# 查询 GeoDNS
dig @127.0.0.1 -p 15353 emby.example.com A
```

### 面板 CLI 参考

**`panel serve [OPTIONS]`** — 启动面板（默认子命令）

| 参数                | 环境变量         | 默认值               | 含义 |
|---------------------|------------------|----------------------|------|
| `--db`              | `PANEL_DB`       | `sqlite://panel.db`  | SQLite URL |
| `--http`            | `PANEL_HTTP`     | `0.0.0.0:8080`       | Web UI/API 绑定 |
| `--dns-addr`        | `PANEL_DNS_ADDR` | `0.0.0.0`            | GeoDNS 绑定地址 |
| `--dns-port`        | `PANEL_DNS_PORT` | `53`                 | GeoDNS 端口（非特权时用高位端口） |
| `--geocn`           | `PANEL_GEOCN`    | （未设置）           | GeoCN.mmdb 路径；缺失则在加载 DB 前返回 SERVFAIL |
| `--ttl`             | `PANEL_TTL`      | `60`                 | 解析 A 记录 TTL（秒） |

**`panel init [OPTIONS]`** — 一次性管理员用户创建 + 数据库迁移

| 参数                | 环境变量         | 默认值               | 含义 |
|---------------------|------------------|----------------------|------|
| `--db`              | `PANEL_DB`       | `sqlite://panel.db`  | SQLite URL |
| `--admin-user`      | —                | `admin`              | 管理员用户名 |
| `--admin-pass`      | —                | （必填）             | 管理员密码（无默认值） |

> **环境变量回退**：所有 `serve` 参数均接受对应的 `PANEL_*` 环境变量，因此已有的基于环境变量的部署继续有效。管理员初始化移至显式的 `init` 子命令——不再有默认密码。

agent 的 CLI 见 [`deploy/agent-install.md`](deploy/agent-install.md)。

---

## 多副本故障转移

### 概述

转发规则现在支持**有序多副本后端**：一条规则可挂一个主后端 + 多个有序备用后端。**agent 自驱动** 按探测周期逐副本探测，通过简单的状态机选出当前可用的最高优先级副本作为活跃上游。当主副本连续失败达到阈值后自动切到备用，备用副本恢复后达到恢复检查次数且过了最小驻留时间才切回主。

**前提**：这些副本必须是同一服务的可互换副本（内容一致），否则语义不成立。

### 术语

- **主后端**：规则编辑时指定的 `backend_host`/`backend_port`，优先级最高。
- **附加副本后端**（`extra_backends`）：规则编辑时添加的有序备用列表 `[第一备选, 第二备选, ...]`，按列表顺序检查。
- **活跃副本**：当前被转发工具（gost/realm）使用的后端。

### 面板规则编辑用法

在面板 Web UI 的**转发规则编辑界面**，可为任一规则添加附加副本后端：

1. **打开规则编辑**：选择规则，进入编辑模式。
2. **配置主后端**：编辑 `backend_host` 和 `backend_port`（已有逻辑，无变化）。
3. **添加附加副本后端**（新）：
   - 点击「添加副本后端」按钮。
   - 输入副本的 `host` 和 `port`。
   - 可添加多个，按添加顺序作为故障转移优先级。
   - 若不需要备用，保留列表为空。
4. **验证并保存**：确保所有后端地址格式正确（同主后端的验证规则），保存规则。

保存时，面板会：
- 验证主、备后端地址合法性。
- 保存到 SQLite（`extra_backends` 为 JSON 序列化的数组）。
- 撞上配置版本号（`desired_config_gen`），重新下发 ConfigPush 给该节点。
- agent 接收新规则，启动故障转移引擎。

### 故障转移语义（据实）

#### 探测与状态机

Agent 按 `probe_interval_secs`（默认 5 秒，面板 HelloOk 下发）周期探测每条规则的所有副本后端。每个后端维护两个计数器：

- **连续失败计数**：探测失败 → +1；探测成功 → 归 0。
- **连续成功计数**：探测成功 → +1；探测失败 → 归 0。

状态机规则：

| 状态 | 触发条件 | 转移 |
|------|--------|------|
| UP（默认）| 连续失败 ≥ `failover_max_fails`（默认 3，约 15 秒）| 转 DOWN |
| DOWN | 连续成功 ≥ `failover_recovery_checks`（默认 6，约 30 秒）**且** 过了 `min_dwell_secs`（默认 60 秒）| 转 UP |

- **快失败**：主副本挂掉需约 15 秒（3 × 5s）才判定不可用。
- **慢恢复**：备用副本恢复需约 30 秒（6 × 5s）的连续成功 + 额外 60 秒最小驻留（防抖），共约 90 秒才切回。这确保了不会因为瞬时抖动频繁切换。

#### 活跃副本选择

每个探测周期，agent 按副本列表顺序（主 → 第一备 → 第二备 → …）选择第一个处于 UP 状态的副本作为活跃副本。

#### 配置重新渲染与重启

当活跃副本集变更时（某规则的活跃副本改变），agent **重新渲染整个节点的 gost/realm 配置**（所有规则的单上游重新生成），然后**重启一次** relay 进程。所有规则变更在一个探测周期内会被**批量处理**、合并到一次重新渲染和一次重启。

**这会导致该节点该转发工具下的所有规则的现有连接短暂中断**。对 Emby 播放体验表现为**可感知的卡顿/重连**。Panel 通过以下机制将切换控制为罕见事件：

- 防抖机制：快失败 + 慢恢复 + 最小驻留，非对称设计。
- 批量处理：同一周期内多个规则变更合并为单次重启。
- 配置不失效：故障副本无法支撑时 agent 保留上次配置（OQ-8），避免crash-loop。

#### 节点 DNS 可用性

Panel 按照"any-up"逻辑：**只要某规则还有一个健康副本，该节点就留在DNS**（线路组的 A 集合里）。只有当某规则的所有副本都不健康时，该规则才被标记为"down"；节点全部规则都 down 才被 GeoDNS 摘除。

### 参数配置

这些参数由面板在 `HelloOk` 消息中下发给 agent，**不需要重发 agent 二进制**。通过**面板环境变量**配置；agent 在下次重连时自动获取新值（无需面板 UI 操作，无需重新部署 agent）：

| 参数 | 环境变量 | 默认值 | 含义 |
|-----|---------|-------|------|
| `probe_interval_secs` | `PANEL_PROBE_INTERVAL_SECS` | 5 | 后端探测周期（秒） |
| `probe_timeout_ms` | `PANEL_PROBE_TIMEOUT_MS` | 1000 | 单次探测超时（毫秒） |
| `failover_max_fails` | `PANEL_FAILOVER_MAX_FAILS` | 3 | 判定副本不可用的连续失败次数 |
| `failover_recovery_checks` | `PANEL_FAILOVER_RECOVERY_CHECKS` | 6 | 判定副本恢复的连续成功次数 |
| `min_dwell_secs` | `PANEL_MIN_DWELL_SECS` | 60 | 切到低优先级副本后的最小驻留时间（秒）|

在启动（或重启）面板前设置相应环境变量；agent 重连时通过 `HelloOk` 获取新值。

### 状态可见性

Agent 每次 StatusReport 都会上报：

- **`backend_health`**：每个后端的探测结果（host, port, reachable）。
- **`active_backends`**：每条规则当前的活跃副本（rule_id, host, port）。

Panel 在**概览/看板**中展示：
- 每个节点每条规则的当前活跃上游。
- 所有后端的探测状态（绿/红）。

### Kill-Switch：回滚兜底

若故障转移出现问题，可通过 **kill-switch** 立即回退到上线前的行为（所有 agent 无视版本、只收单主上游配置）。

#### 启用方式

**方式 1：环境变量（启动）**

```sh
# 启动面板时
export PANEL_FAILOVER_KILLSWITCH=1
panel serve --db "..." --http "..."
```

支持值：`1`、`true`、`yes`、`on`（不区分大小写）。

**方式 2：API（热切）**

查询当前状态：
```bash
curl -s -b cookies.txt http://127.0.0.1:8080/api/settings/failover-killswitch
```

响应：
```json
{ "enabled": false }
```

启用 kill-switch：
```bash
curl -s -b cookies.txt -X PUT -H 'Content-Type: application/json' \
  -d '{"enabled":true}' http://127.0.0.1:8080/api/settings/failover-killswitch
```

#### 行为

**启用时**（`enabled: true`）：

- 面板对**所有在线 agent**（无论版本）只下发**旧式单主上游配置**（等价于本功能上线前的行为）。
- 已连接的 agent 在下一次 ConfigPush/证书更新/心跳超期重连时收到单主配置。
- Agent 不启动故障转移引擎，按原逻辑运行。

**禁用时**（`enabled: false`，默认）：

- 面板下发**结构化多副本配置**（rules 包含 `extra_backends`）。
- Agent 启动故障转移引擎，按故障转移语义运行。

#### 持久化与回退

- Kill-switch 是**内存态，由 `PANEL_FAILOVER_KILLSWITCH` 环境变量播种**。
- 面板重启后会**回到环境变量的默认值**（最安全的应急开关行为：无状态恢复）。
- **若面板发生故障**，重启后默认回到启动时的环境变量设置。建议生产环境保持 `PANEL_FAILOVER_KILLSWITCH=0`（正常运行），仅在需要应急时：
  1. 开启 kill-switch（`PUT /api/settings/failover-killswitch` 或重启时设置环境变量）。
  2. 等待 agent 收到新配置（最多几分钟）。
  3. 观察情况，确认无误后关闭 kill-switch 恢复正常。

### 运维：现网"两规则合一"迁移

若当前有两条规则指向同一服务的两个端口（例如 Emby 主端口 + 备用端口），现在可以合并为一条规则 + 多个副本：

**迁移步骤**（经面板 UI）：

1. **选择保留的规则**（例如主端口）并进入编辑。
2. **添加备用规则的后端作为副本**：
   - 点击「添加副本后端」。
   - 输入备用规则的 `host` 和 `port`。
   - 保存。
3. **验证**：
   - 观察该节点的 StatusReport，检查是否成功上报两个副本。
   - 检查**概览**中该规则的"活跃上游"确实切换到新副本后又切回（模拟故障）。
4. **删除废弃规则**：
   - 确认新规则工作正常后，删除原备用规则。
   - Panel 会自动再次下发配置给节点。

**切换窗口与客户端影响**：

- 删除旧规则后，现网仍连接到**旧端口**的客户端会**断连**（该监听端口已摘除）。
- 需要客户端**改用新规则的端口**或**重新解析域名**（若线路组指向了该节点，域名仍会返回，但端口变了）。
- **不提供自动迁移脚本**：为了避免在线规则的意外变动，迁移必须是手工 + 可观测的。

---

## 测试 + 验证

```sh
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace
cargo fmt --all --check
```

当前状态：**89 个测试通过、0 失败**（1 个 ignored = 需真实 GeoCN.mmdb 的 env-gated 测试）；clippy `-D warnings` 零警告；fmt 干净。

### 真实跨二进制集成冒烟

[`deploy/smoke.sh`](deploy/smoke.sh) 会启动**真实的** panel + agent 二进制（明文 `ws://`、高位 DNS 端口、临时 SQLite），跑完整的 HTTP API + 协议路径，并用 `dig` 查询 GeoDNS：

```sh
cargo build -p panel -p agent
bash deploy/smoke.sh
```

它在两个真实二进制之间验证：面板启动；登录 + 未鉴权返回 401；FrontNode/ForwardRule/DnsZone/LineGroup 创建；agent 的 Hello→HelloOk 握手（面板标记节点已连接）；ConfigPush 下发（agent 写出 gost 配置）+ ConfigAck/漂移路径；StatusReport 存活；以及 GeoDNS 响应。本沙箱**没有真实的 gost/realm 二进制**，故被监管的子进程无法拉起 → 节点判为 Unhealthy → GeoDNS 正确返回 **SERVFAIL**（诚实的结果，而非伪造的 A 记录）。一旦存在真实转发二进制，健康节点就会为该域名返回 A 记录。

---

## 部署

- 面板容器：[`deploy/Dockerfile.panel`](deploy/Dockerfile.panel)（多阶段，内嵌前端，最小运行时）。
- Compose：[`deploy/docker-compose.yml`](deploy/docker-compose.yml)——使用 `network_mode: host`（为无 ECS 回退保留递归器源 IP + 干净的 :53；文件里解释了 Docker UDP NAT 改写源 IP 的坑与 `userland-proxy: false` 备选）。
- agent：[`deploy/agent-install.md`](deploy/agent-install.md)（按节点架构选哪个二进制、环境变量、systemd 单元）以及可选的 [`deploy/Dockerfile.agent`](deploy/Dockerfile.agent)。
- DNS 拓扑操作手册：[`deploy/dns-setup.md`](deploy/dns-setup.md)。

---

## CI/CD

GitHub Actions 自动化测试与发布：

- **CI**（`.github/workflows/ci.yml`）—— 在每次 push/PR 到 `main` 时运行
  `cargo fmt --check`、`clippy -D warnings` 和 `cargo test --workspace`。
- **Release**（`.github/workflows/release.yml`）—— 推送 `v*` 标签时触发；通过
  `cargo-zigbuild` 交叉构建静态 musl agent 二进制（x86_64 + aarch64），构建面板，
  并将所有产物发布到 GitHub Release（自动生成发布说明）。

---

## 更新

### 打标签发布

```sh
git tag v0.1.0
git push --tags
```

CI 自动构建并将二进制发布到 GitHub Releases。

### 面板更新

在 Web UI 中：**系统设置** → **系统更新** → 点击 **检查更新**。如有新版本，点击
**更新面板** —— 面板会下载新二进制、替换自身并自动重启。

### Agent 更新

两种方式：

1. **在节点上重新运行安装脚本** —— 从面板的 `/dl/` 端点下载最新 agent 二进制。
2. **`agent --self-update`** —— agent 将自身二进制与面板上的副本比较，如有不同则
   下载、替换自身并重启。可手动运行或通过 cron 定时执行。

> **注意**：从面板自动推送更新到 agent 是未来增强功能。目前请通过 UI 中的
> **更新 Agent 二进制** 按钮更新面板 dist 目录中的 agent 二进制，然后在各节点
> 重新运行安装脚本或使用 `agent --self-update`。

---

## 验收标准状态

验收标准清单定义在项目计划（`.omc/plans/emby-nat-relay-panel-plan.md`）。下表反映本仓库截至 M1 已实现并被自动化测试覆盖的内容，加上 M3 部署产物。

| AC | 概述 | 状态 |
|----|------|------|
| AC-1  | FrontNode CRUD；token 仅生成一次、可重置、落库前哈希 | 已实现 + 测试（`panel/tests/auth_crud.rs`、冒烟） |
| AC-2  | ForwardRule → 渲染出的 gost 与 realm 配置匹配 golden；按规则选 tool | 已实现 + 测试（configgen golden 测试） |
| AC-3  | LineGroup (区域,运营商)→节点 进入派生记录集；priority 解决重叠 | 已实现 + 测试（`panel/tests/dns_ecs.rs`） |
| AC-4  | 真实/mock agent wss 握手（拒绝无效 token）、ConfigPush/应用/Ack、supersede、漂移重推、协议版本拒绝、token 轮换 | 已实现 + 测试（`panel/tests/ws_mock_agent.rs`、真实二进制冒烟） |
| AC-5  | StatusReport → 心跳过期时 online→offline | 已实现 + 测试（调度器测试、冒烟存活） |
| AC-6  | 带 ECS（电信/联通/移动）的 :53 直查 → 线路组的健康 A 集合；回显 ECS scope | 已实现 + 测试（`panel/tests/dns_ecs.rs`） |
| AC-7  | :53 直查的权威层故障切换 ≤30s；抖动抑制；用户感知层尽力而为 | 状态机已实现 + 测试；≤30s 计时与真实递归器行为需真实环境 |
| AC-8  | 未鉴权管理请求 → 401；有效登录 → 放行；:53 免鉴权 | 已实现 + 测试（`auth_crud.rs`、冒烟 401 检查） |
| AC-9  | `docker compose up` 拉起 panel + :53/udp + :53/tcp + web + 卷；静态 agent；musl 主机拷贝即运行 | 产物已编写（`deploy/`）；真实 `compose up` + 干净主机运行需 Docker/主机环境 |
| AC-10 | 加载真实 GeoCN.mmdb（解码字段）；热替换；格式切换；保留源 IP 网络下的无 ECS 回退 | provider + 热重载 + 格式切换 已实现 + 测试；**真实 GeoCN.mmdb 数据 + 在线无 ECS 回退需真实环境** |
| AC-11 | 配额累计 → 达硬配额移出；重置日加回；面板重启后持久；reset-aware epoch 增量 | 已实现 + 测试（`panel/tests/capacity.rs`） |
| AC-12 | 饱和进入/退出窗口 + 防抖；不影响存量连接；说明缓解延迟 | 已实现 + 测试（`panel/tests/capacity.rs`） |
| AC-13 | 看板：每节点吞吐、配额 %、饱和/健康/在线、精度分级、滚动窗口 | 面板 API + UI 已实现；完整 UI 渲染断言需浏览器/可视化检查 |
| AC-14 | 发布：x86_64 + aarch64 静态 agent；多架构镜像；ARM 运行时按架构选 gost/realm | 双架构构建路径已记录（`BUILD.md`）+ 镜像产物；**真实 aarch64-musl 构建 + ARM 运行时需对应工具链/硬件** |

---

## 需要真实环境 / 已推迟（诚实清单）

以下未声称已完成或已在此验证；它们需要本环境不具备的基础设施、二进制或硬件：

- **真实 `GeoCN.mmdb`** 地理/运营商数据——代码可加载并热重载真实 MMDB，但仓库未内置真实 DB（无 DB 时查询回退为「未知」/SERVFAIL）。
- **真实 `gost`/`realm` 二进制**——agent 监管它们，但本沙箱无真实转发二进制（集成冒烟对此做了说明，并断言诚实的 SERVFAIL，而非伪造健康 A 记录）。
- **真实 Emby 后端**——仅作为可达性探测目标；此处未运行。
- **特权 :53 绑定**——本地运行用高位端口；生产需要 `CAP_NET_BIND_SERVICE` / root / `ip_unprivileged_port_start`（见部署文档）。
- **ARM（aarch64-musl）运行时**——交叉构建路径已记录；真实 ARM 主机运行 + 按架构选 gost/realm 未在此验证（沙箱无 qemu）。
- **面板 TLS**——`wss://` / Web UI 证书（角色 ②）由面板前置（反向代理 + ACME）终结；本阶段面板二进制提供明文 HTTP/ws。
- **DNS 限速（RRL）**——未实现；权威公网 :53 服务器在大规模暴露前应加响应限速。
- **真实 `docker compose up` / 干净 musl 主机拷贝运行**——compose 与 Dockerfile 已编写，但未对真实 Docker 守护进程/全新主机执行。

---

## 许可

MIT（见各 crate 的 `Cargo.toml`）。
