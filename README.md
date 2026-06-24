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

## Quick deploy (one-click scripts, no compilation needed)

Pre-built binaries are published to [GitHub Releases](https://github.com/Bespertrijun/MultiProxy/releases).

### Install panel (control server)

```sh
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-panel.sh | bash -s -- \
  --admin-pass "your-strong-password"
```

The script automatically: downloads the panel binary → initializes the DB and admin user → downloads the GeoCN IP database → installs a systemd service and starts it.

Optional flags:
| Flag | Default | Description |
|------|---------|-------------|
| `--admin-pass` | (required) | Admin password |
| `--dns-port` | `53` | GeoDNS port |
| `--http` | `0.0.0.0:8080` | Web bind |
| `--data-dir` | `/opt/multiproxy` | Data directory |
| `--no-geocn` | - | Skip IP database download |
| `--no-systemd` | - | Don't install systemd service |

### Install agent (each NAT node)

After adding a node in the panel, copy the displayed install command and run it on the NAT node:

```sh
curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-agent.sh | bash -s -- \
  --panel-url wss://panel.example.com/agent \
  --node-id <NODE_ID> --token <TOKEN>
```

The script automatically: detects arch (x86_64/aarch64) → downloads the matching agent binary → downloads gost → installs a systemd service and starts it.

### Full deploy flow

```
1. Run the panel install script on the control server
2. Open the panel → Settings → Configure Cloudflare (auto DNS setup)
3. Add a DNS zone (e.g. emby.example.com)
4. Add a node → copy the install command
5. Paste and run the install command on the NAT node
6. Back in the panel → add forwarding rules → configure line groups
7. Users point their Emby client at the domain name
```

### Updates

The panel supports online self-update:

- **Panel update**: Settings → Check for updates → one-click update (auto-downloads + restarts)
- **Agent update**: `agent --self-update --panel-url wss://...` or re-run the install script
- **Release**: `git tag v0.2.0 && git push --tags` → CI auto-builds and publishes to GitHub Releases

---

## Local development (high DNS port, no privileges)

Run from source (for development):

```sh
# 1. One-time: create the admin user
cargo run -p panel -- init --admin-pass "change-me"

# 2. Start the panel (DNS on a high port so no privileged bind is needed)
cargo run -p panel -- serve \
  --db "sqlite://panel.db" \
  --http "127.0.0.1:8080" \
  --dns-addr "127.0.0.1" \
  --dns-port 15353
```

Verify:

```sh
# log in
curl -c cj.txt -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me"}' http://127.0.0.1:8080/api/login
# create a node
curl -b cj.txt -H 'Content-Type: application/json' \
  -d '{"name":"n1","public_ip":"203.0.113.7"}' http://127.0.0.1:8080/api/nodes
# query the GeoDNS
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

## Multi-replica failover

### Overview

Forwarding rules now support **ordered multi-replica backends**: a single rule can have a primary backend plus multiple ordered standby backends. The **agent self-drives** failover — it probes each replica on a cadence and runs a simple state machine to pick the best-available replica as the active upstream. When the primary fails continuously, it switches to the next standby; when the primary recovers, it must stay healthy for a recovery window and past a minimum dwell time before switching back.

**Precondition**: these replicas must be interchangeable copies of the same service (identical content), or the semantics break down.

### Terminology

- **Primary backend**: the `backend_host`/`backend_port` you specify in rule editing, highest priority.
- **Extra replica backends** (`extra_backends`): ordered standbys `[first_standby, second_standby, ...]` added in rule editing, probed in list order.
- **Active replica**: the backend currently in use by the forwarding tool (gost/realm).

### Panel rule editing usage

In the panel Web UI's **forwarding rule editor**, you can add extra replica backends to any rule:

1. **Open rule editor**: select a rule, enter edit mode.
2. **Configure primary backend**: edit `backend_host` and `backend_port` (existing logic, no change).
3. **Add extra replica backends** (new):
   - Click "Add replica backend" button.
   - Enter the replica's `host` and `port`.
   - Add multiple replicas; they are probed in addition order.
   - Leave empty if no standby is needed.
4. **Validate and save**: ensure all backend addresses pass the same charset checks as the primary; save the rule.

On save, the panel will:
- Validate primary and replica addresses.
- Store in SQLite (`extra_backends` as a JSON-serialized array).
- Bump the config generation (`desired_config_gen`) and re-push ConfigPush to that node.
- The agent receives the new rule and starts the failover engine.

### Failover semantics (as-implemented)

#### Probing and state machine

The agent probes every replica of every rule on the `probe_interval_secs` cadence (default 5 seconds, sent in HelloOk). Each backend tracks two counters:

- **Consecutive failures**: failed probe → +1; successful probe → 0.
- **Consecutive successes**: successful probe → +1; failed probe → 0.

State machine rules:

| State | Trigger | Transition |
|-------|---------|------------|
| UP (default) | Consecutive failures ≥ `failover_max_fails` (default 3, ~15s) | → DOWN |
| DOWN | Consecutive successes ≥ `failover_recovery_checks` (default 6, ~30s) **AND** past `min_dwell_secs` (default 60s) | → UP |

- **Fast-fail**: a dead primary takes ~15 seconds (3 × 5s probe intervals) to be marked unreachable.
- **Slow-recovery**: a recovered standby needs ~30 seconds (6 × 5s) of consecutive success PLUS 60 seconds minimum dwell (~90s total) before switching back. This prevents flapping on transient glitches.

#### Active replica selection

Every probe cycle, the agent walks the replica list (primary → first standby → second standby → …) and picks the first one in UP state as the active replica.

#### Config re-render and restart

When the set of active replicas changes (any rule's active replica shifts), the agent **re-renders the entire node's gost/realm config** (all rules' upstreams regenerated) and **restarts the relay process once**. All changes in a probe cycle are **batched** into a single re-render and restart.

**This causes a brief disruption to all connections on that relay**: Emby playback experiences a **perceptible stall / reconnect**. The panel mitigates by:

- Asymmetric hysteresis: fast-fail, slow-recovery, minimum dwell.
- Batching: multiple rule changes in one cycle merge into one restart.
- Graceful degradation (OQ-8): if all replicas are dead, keep the last known config (no crash-loop).

#### Node DNS availability

The panel uses "any-up" logic: **a node stays in DNS (in the line group's A set) as long as any rule has one healthy replica**. Only when all replicas of a rule are down is that rule marked "down"; only when all rules are down is the node removed from GeoDNS.

### Tunable parameters

These are sent by the panel in `HelloOk` to the agent — **no need to re-release the agent binary**. Values are configured via **panel environment variables**; agents receive the updated values automatically on their next reconnect (no panel UI required, no agent redeploy needed):

| Parameter | Env var | Default | Meaning |
|-----------|---------|---------|---------|
| `probe_interval_secs` | `PANEL_PROBE_INTERVAL_SECS` | 5 | Backend probe cadence (seconds) |
| `probe_timeout_ms` | `PANEL_PROBE_TIMEOUT_MS` | 1000 | Per-probe timeout (milliseconds) |
| `failover_max_fails` | `PANEL_FAILOVER_MAX_FAILS` | 3 | Consecutive failures to mark a replica down |
| `failover_recovery_checks` | `PANEL_FAILOVER_RECOVERY_CHECKS` | 6 | Consecutive successes to mark a replica up |
| `min_dwell_secs` | `PANEL_MIN_DWELL_SECS` | 60 | Minimum dwell time after switching to a lower-priority replica (seconds) |

Set the env vars before starting (or restarting) the panel; agents pick up new values on their next reconnect via `HelloOk`.

### State visibility

Every StatusReport from an agent includes:

- **`backend_health`**: per-backend probe results (host, port, reachable).
- **`active_backends`**: per-rule active replica (rule_id, host, port).

The panel **dashboard/overview** shows:
- Current active upstream for each rule on each node.
- Probe status (green/red) for all backends.

### Kill-switch: emergency rollback

If failover misbehaves, an **emergency kill-switch** reverts all agents (regardless of version) to the pre-launch single-primary behavior instantly.

#### Activation

**Method 1: environment variable (at startup)**

```sh
# When starting the panel
export PANEL_FAILOVER_KILLSWITCH=1
panel serve --db "..." --http "..."
```

Accepts: `1`, `true`, `yes`, `on` (case-insensitive).

**Method 2: API (hot-toggle)**

Check current state:
```bash
curl -s -b cookies.txt http://127.0.0.1:8080/api/settings/failover-killswitch
```

Response:
```json
{ "enabled": false }
```

Enable kill-switch:
```bash
curl -s -b cookies.txt -X PUT -H 'Content-Type: application/json' \
  -d '{"enabled":true}' http://127.0.0.1:8080/api/settings/failover-killswitch
```

#### Behavior

**When enabled** (`enabled: true`):

- The panel sends **legacy single-upstream config** to **all online agents** (any version).
- Connected agents pick up the change on next ConfigPush / cert renewal / heartbeat timeout.
- No failover engine runs; agents behave as before the feature.

**When disabled** (default `enabled: false`):

- The panel sends **structured multi-replica config** (rules with `extra_backends`).
- Agent runs the failover engine per the semantics above.

#### Persistence and recovery

- Kill-switch is **in-memory, seeded from `PANEL_FAILOVER_KILLSWITCH` env var**.
- **Panel restart reverts to the env var default** (safest emergency-only mode: stateless recovery).
- If the panel crashes, restart uses the startup env var. Production recommendation: keep `PANEL_FAILOVER_KILLSWITCH=0` (normal), enable only in emergencies:
  1. Toggle kill-switch (`PUT /api/settings/failover-killswitch` or set env + restart).
  2. Wait for agents to receive the new config (minutes at most).
  3. Observe, confirm normal operation, then toggle off to resume normal mode.

### Operations: migrating "two rules → one rule + replicas"

If you have two separate rules for the same service on different ports (e.g., Emby primary port + backup port), you can now merge them into one rule with multiple replicas:

**Migration (via panel UI)**:

1. **Pick the rule to keep** (e.g., the primary port) and edit it.
2. **Add the backup rule's backend as a replica**:
   - Click "Add replica backend".
   - Enter the backup rule's `host` and `port`.
   - Save.
3. **Verify**:
   - Check the node's StatusReport — both replicas should appear.
   - Check the **overview** — the rule's "active upstream" should show the new replica, then revert (test failover).
4. **Delete the old rule**:
   - Once verified, delete the backup rule.
   - Panel re-pushes config to the node.

**Client impact during migration**:

- Clients still **connected to the old port** will **disconnect** (listener removed).
- Clients must **switch to the new port** or **re-resolve** (if the line group points to this node, the DNS answer changes to the new port).
- **No automatic migration script**: to avoid unintended line changes, this must be manual + observable.

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
