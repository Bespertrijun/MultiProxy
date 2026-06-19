# Deploying the multiProxy agent on a NAT node

The agent is a single, fully-static musl binary with **zero runtime dependencies**.
You copy one file onto the node, set a few env vars, and run it (a systemd unit is
recommended). The agent reverse-connects to the panel over `wss://`, applies the
config the panel pushes, and supervises the local gost/realm forwarding process.

> The agent does **not** open an inbound control port. It dials out to the panel,
> so a NAT node behind a forwarded port range works fine — only the gost/realm
> forwarding listener needs to live inside the node's forwarded port range.

---

## 1. Pick the right binary for the node's CPU arch

The release ships **two static binaries**, one per arch. Copy the one that matches
the node:

| Node arch        | Binary artifact                                          |
|------------------|----------------------------------------------------------|
| x86_64 / amd64   | `target/x86_64-unknown-linux-musl/release/agent`         |
| aarch64 / arm64  | `target/aarch64-unknown-linux-musl/release/agent`        |

Check a node's arch with `uname -m` (`x86_64` → amd64 binary, `aarch64` → arm64).

The agent reports its detected arch to the panel in the `Hello.platform` field
(`x86_64-linux` / `aarch64-linux`); the panel surfaces it for telemetry. The agent
also uses that arch locally to pick the matching gost/realm binary (both tools
publish official arm64 releases). **Wrong-arch binaries will not execute** — verify
with `file ./agent` after copying.

### Building the binaries (cross-build, no native ARM hardware needed)

Cross-build both arches with `cargo-zigbuild` (full toolchain setup is documented
in [`crates/agent/BUILD.md`](../crates/agent/BUILD.md)):

```sh
# x86_64 musl
cargo zigbuild -p agent --release --target x86_64-unknown-linux-musl
# aarch64 musl  (cross-compiled via zig; no ARM box required)
cargo zigbuild -p agent --release --target aarch64-unknown-linux-musl
```

Verify each artifact is static and the correct arch:

```sh
file target/x86_64-unknown-linux-musl/release/agent   # → ELF ... statically linked, stripped
ldd  target/x86_64-unknown-linux-musl/release/agent   # → "not a dynamic executable"
```

See `crates/agent/BUILD.md` for the one-time toolchain setup, the `rust-musl-cross`
Docker alternative, and the multi-arch container manifest build.

---

## 2. Copy the binary onto the node

```sh
# from the build host, for an amd64 node:
scp target/x86_64-unknown-linux-musl/release/agent root@NODE:/usr/local/bin/multiproxy-agent
ssh root@NODE 'chmod +x /usr/local/bin/multiproxy-agent && file /usr/local/bin/multiproxy-agent'
```

Also place the matching-arch `gost` and/or `realm` binary on the node's `PATH`
(the agent spawns `gost -C <cfg>` / `realm -c <cfg>`). The agent writes the tool's
config file into `AGENT_CONFIG_DIR` from the panel's `ConfigPush`; you do not edit
those files by hand.

---

## 3. Configuration (CLI flags with env-var fallback)

The agent accepts CLI flags; each flag also reads a corresponding `AGENT_*`
environment variable as a fallback, so both styles work:

```sh
# CLI style:
multiproxy-agent --panel-url wss://panel.example.com/agent \
                 --node-id <NODE_ID> --token <TOKEN>

# Env style (still works via clap's env feature):
AGENT_PANEL_URL=wss://panel.example.com/agent \
AGENT_NODE_ID=<NODE_ID> AGENT_TOKEN=<TOKEN> multiproxy-agent
```

| Flag                 | Env var              | Required | Default            | Meaning                                                              |
|----------------------|----------------------|----------|--------------------|----------------------------------------------------------------------|
| `--panel-url`        | `AGENT_PANEL_URL`    | yes      | —                  | Panel agent endpoint, e.g. `wss://panel.example.com/agent`           |
| `--node-id`          | `AGENT_NODE_ID`      | yes      | —                  | The node id created in the panel (the `node.id` from `POST /api/nodes`) |
| `--token`            | `AGENT_TOKEN`        | yes      | —                  | The per-node token, shown **once** when the node is created/rotated  |
| `--config-dir`       | `AGENT_CONFIG_DIR`   | no       | `/etc/multiproxy`  | Where gost/realm config files are written                            |
| `--backend-host`     | `AGENT_BACKEND_HOST` | no       | `127.0.0.1`        | Emby backend host the agent probes for reachability                  |
| `--backend-port`     | `AGENT_BACKEND_PORT` | no       | `8096`             | Emby backend port (Emby default 8096)                                |

> `--node-id` must be the **node id**, not the node name. The panel validates
> the token against the node id on the `Hello` handshake — a mismatch is rejected
> as `BadToken`. Token rotation in the panel invalidates the old token immediately.

---

## 4. systemd unit (recommended)

`/etc/systemd/system/multiproxy-agent.service`:

```ini
[Unit]
Description=multiProxy node agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# The agent never needs root for its own control channel. It does need to be able
# to (re)start gost/realm and have those bind the node's forwarded port range.
# Run as root only if your gost/realm listener needs a privileged local port.
ExecStart=/usr/local/bin/multiproxy-agent \
    --panel-url wss://panel.example.com/agent \
    --node-id REPLACE_WITH_NODE_ID \
    --token REPLACE_WITH_NODE_TOKEN \
    --config-dir /etc/multiproxy \
    --backend-host 127.0.0.1 \
    --backend-port 8096
Restart=always
RestartSec=3
# Light hardening (the agent writes only under --config-dir):
ReadWritePaths=/etc/multiproxy
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
mkdir -p /etc/multiproxy
systemctl daemon-reload
systemctl enable --now multiproxy-agent
journalctl -u multiproxy-agent -f
```

On a healthy connect you will see the startup banner
(`agent starting — node=... platform=... protocol=v1 → wss://.../agent`), then the
node turns **online** on the panel dashboard once its first StatusReport lands.

---

## 5. Container alternative (optional)

`deploy/Dockerfile.agent` packages the static binary into a distroless image. On a
NAT node this generally needs **host networking** so gost/realm can bind the
forwarded port range and reach the backend. Prefer the bare-binary + systemd
install above for NAT nodes; use the container only if you understand the
networking implications. Build per arch with the `AGENT_BIN` build arg (see the
Dockerfile header).
