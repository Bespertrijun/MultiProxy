# agent — dual-arch musl build (Line B, rev4 Q1 / AC-14)

The agent ships as a fully-static, zero-runtime-dep single binary per arch:
`x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`.

## Crypto provider
TLS uses **rustls + the `ring` crypto provider** (explicitly NOT `aws-lc-rs`,
whose cmake/NASM toolchain is painful on aarch64-musl). `ring` has a small C/asm
component, so the musl build needs a musl-targeting C compiler. We use **zig** as
that cross-compiler/linker via `cargo-zigbuild`, which avoids installing a
per-arch GNU/musl C toolchain.

## One-time toolchain setup (CI)
```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
# zig (single static download; pin the version in CI):
curl -fsSL https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz \
  | tar -xJ -C /opt
export PATH="/opt/zig-linux-x86_64-0.13.0:$PATH"
cargo install cargo-zigbuild --locked
```

## Build commands (both produce a static, stripped, correct-arch binary)
```sh
# x86_64 musl
cargo zigbuild -p agent --release --target x86_64-unknown-linux-musl
# aarch64 musl  ← the documented ARM cross-compile command (no native ARM HW needed)
cargo zigbuild -p agent --release --target aarch64-unknown-linux-musl
```

Artifacts:
- `target/x86_64-unknown-linux-musl/release/agent`
- `target/aarch64-unknown-linux-musl/release/agent`

Verify each:
```sh
file   target/<triple>/release/agent   # → "ELF ... statically linked, stripped", correct arch
ldd    target/x86_64-unknown-linux-musl/release/agent   # → "not a dynamic executable"
```

## Alternative cross-toolchains (equivalent, for environments without zig)
- `rust-musl-cross` Docker images (`messense/rust-musl-cross:aarch64-musl`):
  ```sh
  docker run --rm -v "$PWD":/home/rust/src messense/rust-musl-cross:aarch64-musl \
    cargo build -p agent --release
  ```
- Native musl GNU toolchain + `cargo build --target ...` after installing
  `musl-tools` / `aarch64-linux-musl-gcc` and setting
  `CC_aarch64_unknown_linux_musl` + `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER`.

## Multi-arch container images (M3 / cross-cutting deploy line)
```sh
docker buildx build --platform linux/amd64,linux/arm64 -t <repo>/agent:<tag> --push .
```

## Per-node forwarding-tool binary (task 2b)
The node's CPU arch is the locally-detected `platform` reported in `Hello`
(`x86_64-linux` / `aarch64-linux`). The agent must use the gost/realm binary
matching that arch (both tools publish official arm64 releases). Selection is a
local lookup (bundled-per-arch or fetched-per-arch); it is not a panel concern
beyond the panel knowing `platform` for UI/telemetry.
