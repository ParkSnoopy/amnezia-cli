# Context

## Vocabulary

- `amn`: the single Rust frontend binary. Without `--tui` it runs the AmneziaVPN CLI; with `--tui` it runs the AmneziaVPN TUI.
- `AmneziaVPN CLI`: the default command-oriented interface exposed by `amn`.
- `AmneziaVPN TUI`: the interactive terminal interface launched only with `amn --tui`; it must expose the same feature operations as the CLI without requiring the user to leave the TUI.
- `core`: shared application logic under `src/core`; CLI and TUI are thin interfaces over the same commands and state transitions.
- `build script`: Cargo `build.rs`, never a shell script.
- `bundle`: the release `amn` executable together with required helper and data artifacts under `libexec/amn`.
- `profile`: an imported VPN configuration stored under the managed profile directory. Runtime network commands use a freshly validated owner-only copy, not the mutable imported pathname.
- `preview`: the TUI form of CLI dry-run behavior; it displays both the planned network action and its rollback without mutating an interface.
- `network mutation`: any command that can create, remove, or alter a real network interface, route, DNS state, or firewall state.
- `rollback`: the opposite action attached to every supported network mutation plan. AmneziaWG/WireGuard use interface ownership evidence; raw XRay records and reverses each route, address, link, and worker-process mutation.
- `ownership`: exact equality between the selected profile's peer public-key set and the live interface peer set; interface-name existence alone is not ownership.
- `dependency preflight`: resolution and validation of all command-line tools, conditional DNS/firewall helpers, privilege requirements, and kernel or userspace backend requirements before a network mutation begins.
- `static frontend`: the `x86_64-unknown-linux-musl` `amn` executable; bundled upstream helpers may retain their own linkage requirements.

## Project Concepts

- Primary direct connections: raw-transport XRay VLESS Reality and AmneziaWG.
- Additional direct connection: WireGuard remains supported but is not a primary acceptance protocol.
- Stored but unsupported direct connections: OpenVPN, Shadowsocks, and IKEv2 are refused until isolated or privileged backends are implemented.
- `raw XRay`: a JSON XRay profile with a VLESS outbound whose transport is `raw` and security is `reality`; imported share links are not the primary raw runtime format.
- Bundled artifacts: `openvpn`, `tun2socks`, `amneziawg-go`, `amnezia-xray-runner`, `geoip.dat`, and `geosite.dat`.
- Build inputs: upstream Conan recipes under `amnezia-client/recipes` and an already configured Amnezia Conan remote.
- Build tools: Rust with the musl target, Conan 2, a C compiler, musl tools, CMake, and Ninja. Make is not an explicit project requirement.
- Runtime trust boundary: real interface changes require root, trusted root-owned executables, a controlled dependency `PATH`, and a root-owned mode-0700 runtime directory.

## Invariants

- Keep one frontend binary and shared logic in `src/core`; preserve `src/cli`, `src/tui`, and `src/main.rs`.
- Prefer enums, traits, and iterator-driven behavior over hardcoded parallel arrays and indexing.
- Fail fast when required build tools, recipes, Conan configuration, artifacts, runtime dependencies, or backends are missing.
- Reject executable profile hooks and mutable `SaveConfig` behavior before privileged execution.
- Persist private state, profiles, backups, logs, and staged configurations with owner-only permissions where supported.
- Never report unsupported protocols or incomplete safety features as connected or protected.
- Keep README.md end-user focused. Maintain project vocabulary in `CONTEXT.md` and release criteria in `RELEASE_GATE.md`; do not add `CHANGELOG.md`.
