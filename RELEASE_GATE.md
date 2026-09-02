# Release Gate

A release is ready only when every applicable gate below passes against the current tree. A successful build alone does not prove real-host VPN behavior.

## Source and package

- `Cargo.toml` and the `amn` entry in `Cargo.lock` contain the same approved version.
- The default invocation remains the CLI and `--tui` remains the only TUI launcher.
- CLI and TUI action coverage remains shared through `src/core`.
- `install` refuses non-root execution and transactionally replaces `/usr/local/bin/amn` and `/usr/local/libexec/amn` from the running executable's adjacent bundle.
- Invalid CLI commands show complete help, and wide plus narrow TUI captures retain readable actions, activity, errors, typed popups, selectable lists, and hierarchical structured output.
- Cargo `build.rs` owns client bundle construction.
- An unchanged complete helper bundle is reused; source changes and missing, added, or modified cached artifacts invalidate it and require a source rebuild.
- New dependencies are documented; existing dependency version changes require explicit approval.

## Build prerequisites

- Rust includes the `x86_64-unknown-linux-musl` target.
- Go, Conan 2, a C compiler, `musl-gcc`, CMake, Ninja, and Make are available.
- The Conan default profile exists.
- The configured `amnezia` remote resolves to `https://artifactory.amnezia.org/artifactory/api/conan/client-prebuilts`.
- Every required recipe and `conanfile.py` exists under `thirdparty/amnezia-client/recipes`.
- The configured branch-tracked source submodules under `thirdparty/` are initialized at their recorded revisions.
- Conan rebuilds executable packages from their recipes; remote executable package binaries are not deployed into the bundle.

## Automated gates

Run from the repository root:

```text
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo run --release --bin amn-bundle
git diff --check
```

The release artifact must also satisfy:

```text
file target/bundle/amn target/bundle/libexec/amn/amnezia-xray-runner target/bundle/libexec/amn/amn-dns
ldd target/bundle/amn target/bundle/libexec/amn/amnezia-xray-runner target/bundle/libexec/amn/amn-dns
```

Required result: `amn` and `amn-dns` are x86-64 static PIE executables, `amnezia-xray-runner` is a static x86-64 Linux executable, `ldd` reports all three as statically linked, and the XRay runner has no `GLIBC_*` version requirements.

The release bundle must contain nonempty validated artifacts at:

```text
target/bundle/amn
target/bundle/libexec/amn/wg
target/bundle/libexec/amn/wg-quick
target/bundle/libexec/amn/wireguard-go
target/bundle/libexec/amn/awg
target/bundle/libexec/amn/awg-quick
target/bundle/libexec/amn/openvpn
target/bundle/libexec/amn/tun2socks
target/bundle/libexec/amn/amneziawg-go
target/bundle/libexec/amn/amnezia-xray-runner
target/bundle/libexec/amn/amn-dns
target/bundle/libexec/amn/geoip.dat
target/bundle/libexec/amn/geosite.dat
```

## Security and mutation gates

- Imported configurations are canonicalized beneath the managed profile directory and revalidated before use.
- Executable hooks and mutable `SaveConfig` directives are rejected, including values with inline comments.
- Real interface actions require root and stage configurations in verified root-owned mode-0700 runtime directories; WireGuard-family quick profiles use a private child of `/etc/wireguard` for AppArmor compatibility, while other backends use `/run/amn`.
- Network executables and every directory in their effective `PATH` are canonical, root-owned, executable where applicable, and not group/world writable.
- Inherited userspace-backend overrides are removed; only a canonical validated backend executable may be forwarded.
- Before mutation, preflight resolves protocol tools, `ip`, quick-script utilities, the bundled DNS helper, conditional firewall utilities, and the required kernel module or userspace backend. AmneziaWG 2 profiles select the bundled source-matched userspace backend rather than trusting an installed kernel module whose feature generation is unknown.
- XRay, WireGuard, and AmneziaWG DNS changes atomically record and replace the resolved `/etc/resolv.conf` target through `amn-dns`; disconnect restores exact prior contents only while the applied contents and target still prove ownership, otherwise it retains recovery state and refuses to overwrite external changes.
- Imported WireGuard and AmneziaWG profiles connect without manual repair when their native configuration omits DNS servers, contains only search domains, or uses the GUI's `$PRIMARY_DNS` and `$SECONDARY_DNS` placeholders; valid per-server DNS values replace placeholders during import, while unresolved placeholders use configured DNS only in the protected runtime copy.
- XRay accepts the Linux-relevant formats, protocols, transports, and authenticated security combinations supported by the configured upstream Amnezia client branch, rejects insecure verification and external security-file inputs, replaces imported inbounds with a loopback-only SOCKS inbound, resolves and pins endpoints before route mutation, blocks IPv6 leakage with a reversible unreachable route, and preflights the bundled runner, `tun2socks`, `ip`, `setsid`, and `kill`. The runner is built as a native static Go executable from the audited upstream source graph, loads normalized configurations without C-archive interop, and binds marked outbound sockets to the recorded uplink.
- Every XRay address, link, endpoint-route, split-default-route, DNS, and worker-process mutation has an in-memory reverse action; only route reverse actions actually created by the current transaction become persisted deletion authority, and every required route is revalidated before connected state is persisted. Persisted deletion commands must also belong to the endpoint and traffic-route set generated for that connection; legacy records without exact route provenance are refused rather than converted from observed routes. Compatible pre-existing bypass routes are reused without being claimed or removed; other pre-existing application-shaped routes fail preflight instead of being claimed. Numeric iproute2 rendering of an unreachable route remains recognizable without weakening destination, protocol, or metric matching. Disconnect retains the full durable ownership record under a disconnect-in-progress marker, rechecks interface absence before every interface-independent persisted route deletion, verifies owned interfaces, routes, and runtime files are absent before success, and restores the worker, DNS, and routes if a later action fails. A restart resumes the marked transaction. If a startup interface disappears before ownership marking, cleanup treats the already-absent interface as rolled back; any remaining process or runtime facts are retained before persistence. Exited zombies do not count as live process-group ownership, and an exact surviving `tun2socks` child in the persisted worker process group is stopped even after the runner exits.
- OpenVPN rejects executable, background, external-credential-file, and interactive-challenge directives; it uses a private staged configuration, fixed interface, isolated process group, startup verification, and a persisted interface index plus random ownership alias. Stale cleanup requires both interface identities and retains the private runtime path for retries.
- Amnezia connection keys are decoded with size-checked Qt-compatible compression and normalized to their preferred supported protocol during import; no generic non-connectable protocol entry is stored.
- Backup restore accepts partial upstream AmneziaVPN settings objects, including a standalone `Servers/serversList`, without requiring an `amn` format marker; every supplied field replaces its corresponding overall setting, including complete replacement of the installed profile list, while omitted settings are preserved.
- Profile lists, selectors, diagnostics, and action prompts expose readable 1-based profile numbers and names rather than internal IDs.
- Every supported connect and disconnect plan has the opposite rollback action.
- WireGuard-family connect marks and persists a random interface ownership alias and kernel interface index in addition to the exact peer set.
- Connect rollback and disconnect remove a WireGuard-family interface only when its persisted index, ownership alias, and exact live peer set all match. State-file replacement syncs both file contents and parent-directory metadata before any journaled external mutation begins. Installation creates and validates the persistent root-owned `/etc/wireguard` staging root; connection transactions never create or claim that shared root. Connect and disconnect persist each exact planned child staging path before creating it, and every removable child carries a matching private ownership marker, so a planned-but-never-created path cannot authorize foreign-directory deletion. Staged runtime ownership remains durable whenever explicit removal needs retry. Disconnect verifies that the interface and staged copy are gone before success. If a stale interface has already vanished, DNS is reverted, but any detectable default-route firewall or policy state—including the exact bundled `wg-quick(8)` and `awg-quick(8)` iptables markers—blocks success and retains recovery state instead of blind deletion.
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
