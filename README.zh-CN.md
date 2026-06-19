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

## 本地运行（高位 DNS 端口，无需特权）

面板使用 CLI 参数（支持环境变量回退）。部署分两步：**`panel init`**（一次性管理员设置）然后 **`panel serve`**（运行）：

```sh
# 1. 一次性：创建管理员用户（密码必填，无默认值）
cargo run -p panel -- init --admin-pass "change-me"

# 2. 启动面板（DNS 用高位端口免去特权绑定）
cargo run -p panel -- serve \
  --db "sqlite://panel.db" \
  --http "127.0.0.1:8080" \
  --dns-addr "127.0.0.1" \
  --dns-port 15353
```

然后走一遍（登录 → 节点 → 规则 → 区域 → 线路组 → 查询）：

```sh
# 登录（保存会话 cookie）
curl -c cj.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}' http://127.0.0.1:8080/api/login
# 创建节点（token 仅展示一次）
curl -b cj.txt -H 'Content-Type: application/json' \
  -d '{"name":"n1","public_ip":"203.0.113.7"}' http://127.0.0.1:8080/api/nodes
# 在高位端口查询 GeoDNS
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
