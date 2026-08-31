# Release Gate

A release is ready only when every applicable gate below passes against the current tree. A successful build alone does not prove real-host VPN behavior.

## Source and package

- `Cargo.toml` and the `amn` entry in `Cargo.lock` contain the same approved version.
- The default invocation remains the CLI and `--tui` remains the only TUI launcher.
- CLI and TUI action coverage remains shared through `src/core`.
- Cargo `build.rs` owns client bundle construction.
- New dependencies are documented; existing dependency version changes require explicit approval.

## Build prerequisites

- Rust includes the `x86_64-unknown-linux-musl` target.
- Conan 2, a C compiler, `musl-gcc`, CMake, and Ninja are available.
- The Conan default profile exists.
- The configured `amnezia` remote resolves to `https://artifactory.amnezia.org/artifactory/api/conan/client-prebuilts`.
- Every required recipe and `conanfile.py` exists under `amnezia-client/recipes`.
- Make is not an explicit frontend build prerequisite.

## Automated gates

Run from the repository root:

```text
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
git diff --check
```

The release artifact must also satisfy:

```text
file target/x86_64-unknown-linux-musl/release/amn
ldd target/x86_64-unknown-linux-musl/release/amn
```

Required result: `amn` is an x86-64 static PIE and `ldd` reports it as statically linked.

The release bundle must contain nonempty validated artifacts at:

```text
target/x86_64-unknown-linux-musl/release/libexec/amn/openvpn
target/x86_64-unknown-linux-musl/release/libexec/amn/tun2socks
target/x86_64-unknown-linux-musl/release/libexec/amn/amneziawg-go
target/x86_64-unknown-linux-musl/release/libexec/amn/amnezia-xray-runner
target/x86_64-unknown-linux-musl/release/libexec/amn/geoip.dat
target/x86_64-unknown-linux-musl/release/libexec/amn/geosite.dat
```

## Security and mutation gates

- Imported configurations are canonicalized beneath the managed profile directory and revalidated before use.
- Executable hooks and mutable `SaveConfig` directives are rejected, including values with inline comments.
- Real interface actions require root and stage configurations in verified root-owned mode-0700 runtime directories; WireGuard-family quick profiles use a private child of `/etc/wireguard` for AppArmor compatibility, while other backends use `/run/amn`.
- Network executables and every directory in their effective `PATH` are canonical, root-owned, executable where applicable, and not group/world writable.
- Inherited userspace-backend overrides are removed; only a canonical validated backend executable may be forwarded.
- Before mutation, preflight resolves protocol tools, `ip`, quick-script utilities, conditional DNS/firewall utilities, and the required kernel module or userspace backend.
- XRay accepts the Linux-relevant formats, protocols, transports, and authenticated security combinations supported by the pinned upstream Amnezia client, rejects insecure verification and external security-file inputs, replaces imported inbounds with a loopback-only SOCKS inbound, resolves and pins endpoints before route mutation, blocks IPv6 leakage with a reversible unreachable route, and preflights the bundled runner, `tun2socks`, `ip`, `setsid`, and `kill`.
- Every XRay address, link, endpoint-route, split-default-route, DNS, and worker-process mutation has a recorded reverse action; disconnect persists its pending state before mutation and restores the worker, DNS, and routes if a later action fails.
- OpenVPN rejects executable, background, external-credential-file, and interactive-challenge directives; it uses a private staged configuration, fixed interface, isolated process group, startup verification, and a persisted interface index plus random ownership alias. Stale cleanup requires both interface identities and retains the private runtime path for retries.
- Amnezia connection keys are decoded with size-checked Qt-compatible compression and normalized to their preferred supported protocol during import; no generic non-connectable protocol entry is stored.
- Backup restore accepts partial upstream AmneziaVPN settings objects, including a standalone `Servers/serversList`, without requiring an `amn` format marker; supplied compatible settings and profiles are merged while omitted local state is preserved.
- Every supported connect and disconnect plan has the opposite rollback action.
- WireGuard-family connect marks and persists a random interface ownership alias and kernel interface index in addition to the exact peer set.
- Connect rollback and disconnect remove a WireGuard-family interface only when its persisted index, ownership alias, and exact live peer set all match; failed persistence either restores actionable ownership metadata or retries teardown toward the persisted disconnected state.
- Reconnect repeats the same owned disconnect/connect lifecycle; failed rollback records are marked as recovery-required rather than reported as healthy, and status reports Linux interface traffic counters when available.

## Runtime acceptance

Complete these gates on an isolated Linux host or disposable VM with root access for OpenVPN, WireGuard, AmneziaWG, and XRay:

1. Run `amn doctor` and confirm every required runtime dependency passes.
2. Connect each supported protocol and verify the intended interface, addresses, routes, DNS behavior, and traffic path.
3. Disconnect each supported protocol and verify interface, routes, DNS, and firewall state return to their baseline.
4. Inject a command failure after interface creation and verify connect rollback removes only the created profile-owned interface.
5. Inject a persistence failure after successful connect and after successful disconnect; verify the opposite action restores the pre-operation state.
6. Create a same-named interface with a different or additional peer and verify mutation and rollback are refused.
7. For every supported XRay format and transport, verify the endpoint remains on the original uplink, selected route mode uses `amnxray0`, DNS resolves through the connection, all-traffic modes prevent IPv6 leakage, the worker process group stops cleanly, and injected DNS/route/process failures restore every earlier mutation.
8. For OpenVPN, verify inline-certificate and inline-credential profiles connect, route modes work, pushed DNS is applied, `amnovpn0` disappears on disconnect, and process/persistence failures restore the previous state.
9. Import a real `vpn://` key for each supported Amnezia container and verify the preferred native protocol is selected and connectable.

Record real-host runtime acceptance separately from automated build/test results. If these runtime gates have not been performed, the release remains unverified for privileged VPN behavior.
