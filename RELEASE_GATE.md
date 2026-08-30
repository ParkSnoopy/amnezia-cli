# Release Gate

A release is ready only when every applicable gate below passes against the current tree. A successful build alone does not prove real-host VPN behavior.

## Source and package

- `Cargo.toml` and the `amn` entry in `Cargo.lock` contain the same approved version.
- The default invocation remains the CLI and `--tui` remains the only TUI launcher.
- CLI and TUI action coverage remains shared through `src/core`.
- No `scripts/` build path or `CHANGELOG.md` is introduced; Cargo `build.rs` owns bundle construction.
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
- Raw XRay accepts only JSON VLESS Reality profiles using the `raw` transport, replaces imported inbounds with a loopback-only SOCKS inbound, resolves and pins the endpoint before route mutation, blocks IPv6 leakage with a reversible unreachable route, and preflights the bundled runner, `tun2socks`, `ip`, `setsid`, and `kill`.
- Every raw XRay address, link, endpoint-route, split-default-route, and worker-process mutation has a recorded reverse action; disconnect persists its pending state before mutation and restores the worker and routes if a later action fails.
- Shadowsocks accepts SIP002 links and Shadowsocks XRay JSON, normalizes both to a loopback-only SOCKS inbound, and uses the same endpoint-pinned XRay lifecycle and rollback gates.
- OpenVPN rejects executable, background, external-credential-file, and interactive-challenge directives; it uses a private staged configuration, fixed owned interface, isolated process group, startup interface verification, and process-group rollback.
- IKEv2 accepts validated Amnezia JSON with a PKCS#12 certificate, stages only the decoded certificate privately, passes its password through stdin rather than argv, persists the exact endpoint-route identity, verifies kernel or kernel-libipsec readiness, and owns an isolated `charon-cmd` process group. Endpoint pinning refuses pre-existing route/rule ownership and rolls back only mutations completed by the current connection attempt. Disconnect and rollback verify removal of `ipsec0`, its table-220 routes, endpoint rules/routes, and endpoint XFRM state and policy before reporting success.
- Amnezia connection keys are decoded with size-checked Qt-compatible compression and normalized to their preferred supported protocol during import; no generic non-connectable protocol entry is stored.
- Every supported connect and disconnect plan has the opposite rollback action.
- Connect rollback removes an interface only when its exact live peer set matches the selected profile.
- Disconnect refuses an absent interface or an interface whose exact peer set differs from the selected profile; failed persistence restores the selected profile only after a verified owned interface transition.

## Runtime acceptance

Complete these gates on an isolated Linux host or disposable VM with root access for OpenVPN, WireGuard, AmneziaWG, raw XRay VLESS Reality, Shadowsocks, and IKEv2:

1. Run `amn doctor` and confirm every required runtime dependency passes.
2. Connect each supported protocol and verify the intended interface, addresses, routes, DNS behavior, and traffic path.
3. Disconnect each supported protocol and verify interface, routes, DNS, and firewall state return to their baseline.
4. Inject a command failure after interface creation and verify connect rollback removes only the created profile-owned interface.
5. Inject a persistence failure after successful connect and after successful disconnect; verify the opposite action restores the pre-operation state.
6. Create a same-named interface with a different or additional peer and verify mutation and rollback are refused.
7. For raw XRay and Shadowsocks, verify the endpoint remains on the original uplink, selected route mode uses `amnxray0`, all-traffic modes prevent IPv6 leakage, the worker process group stops cleanly, and injected route/process failures restore every earlier mutation.
8. For OpenVPN, verify inline-certificate and inline-credential profiles connect, route modes work, pushed DNS is applied, `amnovpn0` disappears on disconnect, and process/persistence failures restore the previous state.
9. For IKEv2, verify PKCS#12 authentication, installed IPsec policies/routes, DNS behavior, process cleanup, and failure rollback.
10. Import a real `vpn://` key for each available Amnezia container and verify the preferred native protocol is selected and connectable.

Record real-host runtime acceptance separately from automated build/test results. If these runtime gates have not been performed, the release remains unverified for privileged VPN behavior.
