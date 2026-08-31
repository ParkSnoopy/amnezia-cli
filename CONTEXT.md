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
- `dependency preflight`: resolution and validation of all command-line tools, conditional DNS/firewall helpers, privilege requirements, and kernel or userspace backend requirements before a network mutation begins.
- `static frontend`: the `x86_64-unknown-linux-musl` `amn` executable; bundled upstream helpers may retain their own linkage requirements.

## Project Concepts

- Direct connections: OpenVPN, WireGuard, AmneziaWG, and general XRay.
- OpenVPN owns a fixed `amnovpn0` interface and an isolated process group; accepted profiles are self-contained and non-interactive.
- `XRay`: the Linux-relevant XRay formats, protocols, transports, and security combinations supported by the configured upstream Amnezia client branch; support is not limited to VLESS Reality or the `raw` transport. Imported inbounds, bypass outbounds, and routing rules are not trusted: normalization retains one supported proxy outbound, installs the loopback inbound owned by the Linux runner, and forces that inbound through the retained outbound. Rejecting malformed links and unknown transport or security values that upstream may pass through is an intentional Linux safety deviation.
- Bundled artifacts: source-built `wg`, `wg-quick`, `wireguard-go`, `awg`, `awg-quick`, `openvpn`, `tun2socks`, `amneziawg-go`, and `amnezia-xray-runner`, plus validated `geoip.dat` and `geosite.dat` data.
- Installation: `amn init` requires root, reads only the complete bundle relative to the running executable, and installs the command under `/usr/local/bin` with its programs under `/usr/local/libexec/amn`.
- Interface: the TUI uses a dark canvas, light text, hairline cards, restrained blue focus, grouped human-readable actions, and responsive wide and narrow layouts.
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
