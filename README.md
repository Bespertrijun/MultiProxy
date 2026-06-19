# multiProxy — Emby multi-front NAT relay + GeoDNS line splitting

![CI](https://github.com/Bespertrijun/MultiProxy/actions/workflows/ci.yml/badge.svg)

English | [简体中文](README.zh-CN.md)

multiProxy fronts a single backend (e.g. an **Emby** media server) with a fleet of
**NAT relay nodes** spread across ISPs/regions, and steers each client to the best
front via a **self-built GeoDNS** that splits answers by the client's geo/ISP line.
A central **panel** manages the fleet, renders the per-node forwarding config,
tracks node health + capacity, and serves the DNS answers; a thin **agent** on each
NAT node reverse-connects to the panel, applies pushed config, supervises the local
forwarding tool (gost/realm), and self-reports.

> Status: M0 + M1 are complete and validated; M3 deploy/docs artifacts and a real
> cross-binary integration smoke are in `deploy/`. See the AC status and the
> "Needs real infra / deferred" list at the bottom — nothing here is claimed to be
> deployed or tested in production.

---

## Why this exists

External DNS providers (Cloudflare, DNSPod, …) cannot split answers by mainland
China ISP line. multiProxy keeps a **self-hosted authoritative GeoDNS** for the
resolution name and uses **EDNS Client Subnet (ECS)** — or, when absent, the
recursor source IP — to geolocate the client and return the front node(s) on the
matching line. End users point their Emby client at the resolution name; they reach
a front node that NATs/relays them to the real backend.

---

## Architecture

```
                 ┌──────────────────────────── panel host (non-NAT, public IP, :53) ─┐
   end user      │   ┌─────────────┐        ┌──────────────────────────────────────┐ │
  (Emby client)  │   │  GeoDNS     │  reads │  panel (axum)                         │ │
       │  dig    │   │ (hickory,   │◄───────┤  • CRUD: nodes / rules / zones /      │ │
       ├────────►│   │  :53 udp/tcp│ snap-  │    line-groups + auth (sessions)      │ │
       │  A rec  │   │  isolated   │ shot   │  • config render (gost/realm)         │ │
       │◄────────┤   │  runtime)   │        │  • WS reverse-server  /agent          │ │
       │         │   └─────────────┘        │  • health + capacity scheduler        │ │
       │         │                          │  • SQLite (bundled libsqlite3)        │ │
       │         └──────────────────────────┴──────────────────────────────────────┘ │
       │                                            ▲  wss:// reverse-connect          │
       │                                            │  Hello/HelloOk/ConfigPush/Ack    │
       │                                            │  Heartbeat/StatusReport          │
  ┌────┴─────── front NAT node ───────────┐         │                                  │
  │  agent (static musl)                  ├─────────┘                                  │
  │   • applies ConfigPush → writes cfg   │                                            │
  │   • supervises gost/realm child       │   relay                                    │
  │   • probes backend, reports capacity  ├──────────────►  Emby backend               │
  └───────────────────────────────────────┘                                           │
```

### The two DNS roles (do not collapse them)

1. **Resolution domain ①** (e.g. `emby.example.com`) — served by the **embedded
   GeoDNS**. Does the geo/ISP splitting. Delegated to the GeoDNS host via an NS
   record in Cloudflare (grey-cloud). End users point Emby here.
2. **Panel control domain ②** (e.g. `panel.example.com`) — kept on a **stable
   external provider** (CF/DNSPod), NOT the embedded GeoDNS, so a panel/GeoDNS
   outage can't stop agents from resolving the panel to reconnect. Also drives the
   DNS-01 ACME cert for ②.

Full runbook: [`deploy/dns-setup.md`](deploy/dns-setup.md).

---

## Crate layout

Cargo workspace (`Cargo.toml`), four crates:

| Crate              | Role |
|--------------------|------|
| `crates/contract`  | Transport-agnostic wire protocol (JSON envelope: Hello / HelloOk / ConfigPush / ConfigAck / Heartbeat / StatusReport / AuthReject / Close), data model, ISP/region types, protocol versioning. Intentionally minimal deps (only serde) so the agent stays musl-thin. **Do not change its semantics lightly.** |
| `crates/geoip`     | IP → (region, ISP) lookup behind a `GeoIpProvider` trait; GeoCN MMDB provider + hot-reloadable `ProviderHandle` (ArcSwap); a format-switch stub. ipip/纯真 adapters deferred. |
| `crates/panel`     | Management plane: CRUD + auth, gost/realm config rendering, WS reverse-server, health/capacity scheduler, and the in-process GeoDNS (hickory) on an isolated runtime. SQLite via sqlx + bundled libsqlite3. |
| `crates/agent`     | Thin static per-node agent: wss reverse-connect with backoff, config apply, gost/realm process supervision + self-heal, capacity telemetry. Dual-arch musl, rustls + ring. |

---

## Build

Standard workspace build (host arch):

```sh
cargo build --workspace            # debug
cargo build --release --workspace  # release (panel + agent + libs)
```

### Dual-arch static musl agent

The agent ships as a fully-static, zero-runtime-dep binary per arch. Cross-build
both with `cargo-zigbuild` (no native ARM hardware needed):

```sh
cargo zigbuild -p agent --release --target x86_64-unknown-linux-musl
cargo zigbuild -p agent --release --target aarch64-unknown-linux-musl
```

Toolchain setup, verification (`file` / `ldd`), and the multi-arch container
manifest are documented in [`crates/agent/BUILD.md`](crates/agent/BUILD.md).

---

## Run locally (high DNS port, no privileges)

The panel uses CLI parameters with env-var fallback. The deploy flow is two steps:
**`panel init`** (one-time admin setup) then **`panel serve`** (run):

```sh
# 1. One-time: create the admin user (password is required, no default)
cargo run -p panel -- init --admin-pass "change-me"

# 2. Start the panel (DNS on a high port so no privileged bind is needed)
cargo run -p panel -- serve \
  --db "sqlite://panel.db" \
  --http "127.0.0.1:8080" \
  --dns-addr "127.0.0.1" \
  --dns-port 15353
```

Then exercise it (login → node → rule → zone → line group → query):

```sh
# log in (stores a session cookie)
curl -c cj.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}' http://127.0.0.1:8080/api/login
# create a node (token is shown once)
curl -b cj.txt -H 'Content-Type: application/json' \
  -d '{"name":"n1","public_ip":"203.0.113.7"}' http://127.0.0.1:8080/api/nodes
# query the GeoDNS on the high port
dig @127.0.0.1 -p 15353 emby.example.com A
```

### Panel CLI reference

**`panel serve [OPTIONS]`** — start the panel (default subcommand)

| Flag              | Env var          | Default              | Meaning |
|-------------------|------------------|----------------------|---------|
| `--db`            | `PANEL_DB`       | `sqlite://panel.db`  | SQLite URL |
| `--http`          | `PANEL_HTTP`     | `0.0.0.0:8080`       | Web UI/API bind |
| `--dns-addr`      | `PANEL_DNS_ADDR` | `0.0.0.0`            | GeoDNS bind address |
| `--dns-port`      | `PANEL_DNS_PORT` | `53`                 | GeoDNS port (use a high port unprivileged) |
| `--geocn`         | `PANEL_GEOCN`    | (unset)              | GeoCN.mmdb path; absent → SERVFAIL until loaded |
| `--ttl`           | `PANEL_TTL`      | `60`                 | Resolution A-record TTL secs |

**`panel init [OPTIONS]`** — one-time admin user + DB migration

| Flag              | Env var          | Default              | Meaning |
|-------------------|------------------|----------------------|---------|
| `--db`            | `PANEL_DB`       | `sqlite://panel.db`  | SQLite URL |
| `--admin-user`    | —                | `admin`              | Admin username |
| `--admin-pass`    | —                | (required)           | Admin password (no default) |

> **Env-var fallback**: all `serve` flags accept their `PANEL_*` env var, so existing
> env-based deploys continue to work. The admin seed moved to the explicit `init`
> subcommand — there is no default password.

The agent's CLI is in [`deploy/agent-install.md`](deploy/agent-install.md).

---

## Test + verify

```sh
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace
cargo fmt --all --check
```

### Real cross-binary integration smoke

[`deploy/smoke.sh`](deploy/smoke.sh) starts the **real** panel + agent binaries
(plain `ws://`, high DNS port, temp SQLite), drives the full HTTP API + protocol
path, and queries the GeoDNS with `dig`:

```sh
cargo build -p panel -p agent
bash deploy/smoke.sh
```

It verifies, across the two real binaries: panel startup; login + 401-on-unauth;
FrontNode/ForwardRule/DnsZone/LineGroup creation; the agent's Hello→HelloOk
handshake (panel marks the node connected); ConfigPush delivery (the agent writes
the gost config) + the ConfigAck/drift path; StatusReport liveness; and the GeoDNS
response. In this sandbox there is **no real gost/realm binary**, so the supervised
child cannot spawn → the node is Unhealthy → the GeoDNS correctly returns
**SERVFAIL** (the honest outcome, not a faked A record). With a real forwarding
binary present, a healthy node yields an A record for the zone name.

---

## Deploy

- Panel container: [`deploy/Dockerfile.panel`](deploy/Dockerfile.panel) (multi-stage,
  embedded frontend, minimal runtime).
- Compose: [`deploy/docker-compose.yml`](deploy/docker-compose.yml) — uses
  `network_mode: host` (preserves the recursor source IP for the no-ECS fallback +
  clean :53; the file explains the Docker-UDP-NAT source-IP-rewrite pitfall and the
  `userland-proxy: false` alternative).
- Agent: [`deploy/agent-install.md`](deploy/agent-install.md) (which binary per node
  arch, env vars, systemd unit) and optional
  [`deploy/Dockerfile.agent`](deploy/Dockerfile.agent).
- DNS topology runbook: [`deploy/dns-setup.md`](deploy/dns-setup.md).

---

## CI/CD

GitHub Actions automates testing and releases:

- **CI** (`.github/workflows/ci.yml`) — runs `cargo fmt --check`, `clippy -D warnings`,
  and `cargo test --workspace` on every push/PR to `main`.
- **Release** (`.github/workflows/release.yml`) — triggered by pushing a `v*` tag;
  cross-builds static musl agent binaries (x86_64 + aarch64) via `cargo-zigbuild`,
  builds the panel, and publishes all artifacts to a GitHub Release with auto-generated
  release notes.

---

## Updates

### Tagging a release

```sh
git tag v0.1.0
git push --tags
```

CI auto-builds and publishes binaries to GitHub Releases.

### Panel update

From the web UI: **System Settings** (系统设置) > **System Update** (系统更新) > click
**Check Update** (检查更新). If a new version is available, click **Update Panel**
(更新面板) — the panel downloads the new binary, replaces itself, and restarts
automatically.

### Agent update

Two options:

1. **Re-run the install script** on the node — it downloads the latest agent binary
   from the panel's `/dl/` endpoint.
2. **`agent --self-update`** — the agent compares its binary against the panel's copy,
   downloads if different, replaces itself, and restarts. Can be run manually or via a
   cron job.

> **Note**: automatic push-update of agents from the panel is a future enhancement.
> For now, update the agent binaries in the panel's dist directory via the UI
> (**Update Agent Binaries** button), then re-run the install script on each node
> or use `agent --self-update`.

---

## Acceptance criteria status

The AC list is defined in the project plan (`.omc/plans/emby-nat-relay-panel-plan.md`).
Status reflects what is implemented + covered by automated tests in this repo
through M1, plus the M3 deploy artifacts.

| AC | Summary | Status |
|----|---------|--------|
| AC-1  | FrontNode CRUD; token generated once, regenerable, hashed at rest | Implemented + tested (`panel/tests/auth_crud.rs`, smoke) |
| AC-2  | ForwardRule → rendered gost AND realm config match goldens; per-rule tool selector | Implemented + tested (configgen golden tests) |
| AC-3  | LineGroup (region,ISP)→nodes appears in derived record set; priority resolves overlap | Implemented + tested (`panel/tests/dns_ecs.rs`) |
| AC-4  | Real/mock agent wss handshake (reject invalid token), ConfigPush/apply/Ack, supersede, drift re-push, protocol-version reject, token rotation | Implemented + tested (`panel/tests/ws_mock_agent.rs`, real-binary smoke) |
| AC-5  | StatusReport → online→offline when heartbeat stale | Implemented + tested (scheduler tests, smoke liveness) |
| AC-6  | Direct :53 query with ECS (电信/联通/移动) → line group's healthy A set; ECS scope echoed | Implemented + tested (`panel/tests/dns_ecs.rs`) |
| AC-7  | Authoritative failover ≤30s on direct :53 query; flap-damping; user-perceived best-effort | State-machine implemented + tested; the ≤30s timing + real recursor behavior need real infra |
| AC-8  | Unauthenticated mgmt → 401; valid login → access; :53 auth-exempt | Implemented + tested (`auth_crud.rs`, smoke 401 check) |
| AC-9  | `docker compose up` brings panel + :53/udp + :53/tcp + web + volumes; static agent; copy-run on musl host | Artifacts authored (`deploy/`); a real `compose up` + clean-host run need Docker/host infra |
| AC-10 | Load real GeoCN.mmdb (decoded fields); hot-swap reload; format-switch; no-ECS fallback under source-IP-preserving net | Provider + hot-reload + format-switch implemented + tested; **real GeoCN.mmdb data + the live no-ECS fallback need real infra** |
| AC-11 | Quota accumulation → removal at hard quota; reset-day re-add; persist across panel restart; reset-aware epoch deltas | Implemented + tested (`panel/tests/capacity.rs`) |
| AC-12 | Saturation enter/exit windows + debounce; established flows unaffected; documented relief latency | Implemented + tested (`panel/tests/capacity.rs`) |
| AC-13 | Dashboard: per-node throughput, quota %, saturation/health/online, accuracy tier, rolling window | Panel API + UI implemented; full UI render assertion needs a browser/visual pass |
| AC-14 | Release: x86_64 + aarch64 static agents; multi-arch images; ARM runtime selects matching gost/realm | Dual-arch build path documented (`BUILD.md`) + image artifacts; **a real aarch64-musl build + ARM runtime need that toolchain/hardware** |

---

## Needs real infra / deferred (honest list)

These are not claimed to be done or tested here; they require infrastructure,
binaries, or hardware not present in this environment:

- **Real `GeoCN.mmdb`** geo/ISP data — code loads + hot-reloads a real MMDB, but no
  real DB is bundled (queries fall back to "unknown" / SERVFAIL without one).
- **Real `gost`/`realm` binaries** — the agent supervises them, but no real
  forwarding binary is present in this sandbox (the integration smoke documents this
  and asserts the honest SERVFAIL rather than faking a healthy A record).
- **Real Emby backend** — used only as a reachability probe target; not run here.
- **Privileged :53 bind** — local runs use a high port; production needs
  `CAP_NET_BIND_SERVICE` / root / `ip_unprivileged_port_start` (see deploy docs).
- **ARM (aarch64-musl) runtime** — cross-build path is documented; an actual ARM
  host run + matching-arch gost/realm selection is not exercised here.
- **Panel TLS** — `wss://` / the web UI cert (role ②) is terminated in front of the
  panel (reverse proxy + ACME); the panel binary serves plain HTTP/ws in this phase.
- **DNS rate-limiting (RRL)** — not implemented; an authoritative public :53 server
  should add response-rate-limiting before heavy exposure.
- **Live `docker compose up` / clean-musl-host copy-run** — compose + Dockerfiles are
  authored but not executed against a real Docker daemon / fresh host here.
```
