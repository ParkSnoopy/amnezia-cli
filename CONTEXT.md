# Context

## Vocabulary

- `amn`: the single Rust frontend binary. Without `--tui` it runs the AmneziaVPN CLI; with `--tui` it runs the AmneziaVPN TUI.
- `AmneziaVPN CLI`: the default command-oriented interface exposed by `amn`.
- `AmneziaVPN TUI`: the interactive terminal interface launched only with `amn --tui`; it must expose the same feature operations as the CLI without requiring the user to leave the TUI.
- `core`: shared application logic under `src/core`; CLI and TUI are thin interfaces over the same commands and state transitions.
- `build script`: Cargo `build.rs`, never a shell script.
- `bundle`: the release `amn` executable together with required helper and data artifacts in the portable `target/bundle` tree.
- `profile`: an imported VPN configuration stored under the managed profile directory. Runtime network commands use a freshly validated owner-only copy, not the mutable imported pathname.
- `preview`: the TUI form of CLI dry-run behavior; it displays both the planned network action and its rollback without mutating an interface.
- `network mutation`: any command that can create, remove, or alter a real network interface, route, DNS state, or firewall state.
- `connection transaction`: the coherent lifecycle joining dependency preflight, network mutations, readiness, ownership, durable connection state, rollback, and recovery for one selected profile.
- `connections interface`: the shared caller surface exposing status, preview, connect, disconnect, and reconnect; status reconciliation keeps recovery internal rather than exposing transaction mechanics to CLI or TUI callers.
- `rollback`: the opposite action attached to every supported network mutation plan. AmneziaWG/WireGuard use interface ownership evidence; XRay records and reverses each route, address, link, and worker-process mutation; OpenVPN owns an isolated process group and private runtime material.
- `Amnezia bundle`: a `vpn://` connection key or JSON full-access bundle. Import selects the preferred supported container and stores only its normalized native protocol profile; it is not retained as a fake protocol.
- `ownership`: exact equality between the selected profile's peer public-key set and the live interface peer set; interface-name existence alone is not ownership.
- `dependency preflight`: resolution and validation of all command-line tools, conditional DNS/firewall helpers, privilege requirements, and kernel or userspace backend requirements before a network mutation begins. AmneziaWG 2 fields select the bundled source-matched userspace backend because the presence of an installed `amneziawg` module does not prove support for that configuration generation.
- `static frontend`: the `x86_64-unknown-linux-musl` `amn` executable; the DNS helper is also a static musl executable and the native Go XRay runner is a static Linux executable, while other bundled upstream helpers retain their audited linkage requirements.

## Project Concepts

- Direct connections: OpenVPN, WireGuard, AmneziaWG, and general XRay.
- OpenVPN owns a fixed `amnovpn0` interface and an isolated process group; accepted profiles are self-contained and non-interactive.
- `XRay`: the Linux-relevant XRay formats, protocols, transports, and security combinations supported by the configured upstream Amnezia client branch; support is not limited to VLESS Reality or the `raw` transport. Imported inbounds, bypass outbounds, and routing rules are not trusted: normalization retains one supported proxy outbound, installs the loopback inbound owned by the Linux runner, and forces that inbound through the retained outbound. Rejecting malformed links and unknown transport or security values that upstream may pass through is an intentional Linux safety deviation.
- Bundled artifacts: source-built `wg`, `wg-quick`, `wireguard-go`, `awg`, `awg-quick`, `openvpn`, `tun2socks`, `amneziawg-go`, `amnezia-xray-runner`, and `amn-dns`, plus validated `geoip.dat` and `geosite.dat` data. The XRay runner is built directly as a static Go executable from the audited upstream XRay source graph; it does not cross a C archive boundary or depend on the build host's glibc.
- DNS lifecycle: XRay, WireGuard, and AmneziaWG use the bundled `amn-dns` helper. It records the exact resolver target, mode, previous contents, and applied contents under protected runtime state, atomically applies DNS, restores only when ownership still matches, and retains recovery state instead of overwriting an external resolver change. WireGuard-family runtime profiles resolve GUI-exported `$PRIMARY_DNS` and `$SECONDARY_DNS` values from their server record during import; existing profiles with unresolved placeholders use the configured DNS servers in the protected runtime copy, without rewriting the stored import.
- Process lifecycle: exited zombie processes do not count as live process-group ownership. XRay startup rollback escalates from graceful termination to an exact owned process-group force-stop, and a later connect reconciles retained stale XRay state before starting another profile.
- Bundle cache: Cargo `build.rs` reuses the complete locally built helper bundle only when both its source inputs and every cached artifact still match their recorded content fingerprints; changed, missing, or partial bundles are rebuilt from source.
- Installation: `amn install` requires root, reads only the complete bundle relative to the running executable, and installs the command under `/usr/local/bin` with its programs under `/usr/local/libexec/amn`.
- Interface: the TUI uses a dark canvas, light text, hairline cards, restrained blue focus, grouped human-readable actions, and responsive wide and narrow layouts. Actions that need values use typed popups or selectable lists rather than command-text entry; structured output is rendered as hierarchical entries.
- CLI errors: an invalid command prints both the parser error and the complete command help.
- Build inputs: branch-tracked GitHub source submodules under `thirdparty/`, upstream Conan recipes under `thirdparty/amnezia-client/recipes`, and an already configured Amnezia Conan remote; executable packages are rebuilt from source rather than deployed from remote binaries.
- Build tools: Rust with the musl target, Go, Conan 2, a C compiler, musl tools, CMake, Ninja, and Make.
- Runtime trust boundary: real interface changes require root, trusted root-owned executables, a controlled dependency `PATH`, and a root-owned mode-0700 runtime directory.

## Invariants

- Keep one frontend binary and shared logic in `src/core`; preserve `src/cli`, `src/tui`, and `src/main.rs`.
- Keep protocol-specific parsing and validation in one file per protocol; keep shared encoding, routing, lifecycle, persistence, and rollback behavior generic rather than duplicating it between protocols.
- Prefer enums, traits, and iterator-driven behavior over hardcoded parallel arrays and indexing.
- Keep profile IDs internal; CLI and TUI profile selection and presentation use the current displayed order starting at 1.
- Fail fast when required build tools, recipes, Conan configuration, artifacts, runtime dependencies, or backends are missing.
- Reject executable profile hooks and mutable `SaveConfig` behavior before privileged execution.
- Persist private state, profiles, backups, logs, and staged configurations with owner-only permissions where supported.
- Treat backup restore as an interoperable partial update: accept upstream AmneziaVPN settings keys without an `amn` envelope, replace each supplied overall setting (including the complete server/profile list), and preserve only omitted settings.
- Never import a profile as connectable unless its protocol-specific configuration validates; never report an incomplete connection as connected or protected.
- Keep README.md end-user focused. Maintain project vocabulary in `CONTEXT.md` and release criteria in `RELEASE_GATE.md`; do not add `CHANGELOG.md`.
