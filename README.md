# AmneziaVPN TUI

AmneziaVPN TUI manages and connects AmneziaVPN profiles from an interactive TUI or CLI.

## Build

Install Rust with the `x86_64-unknown-linux-musl` target, Conan 2, a C compiler, musl tools, CMake, and Ninja, then build the release bundle:

```text
cargo build --release
```

Cargo builds `amn` as a statically linked musl executable and builds the required recipes from `amnezia-client/recipes/`. Missing tools, recipes, recipe outputs, or the Conan default profile stop the build. The resulting `amn` and its `libexec/amn` files form the release bundle.

## Usage

Open interactive terminal dashboard with `--tui`:

```text
amn --tui
```

Import a native VPN profile, inspect it, and connect:

```text
amn profile import ~/vpn/home.conf --name Home
amn profile list
amn connect
amn status
amn disconnect
```

Imported native profile formats:

- OpenVPN
- WireGuard
- AmneziaWG
- XRay
- Shadowsocks
- IKEv2

Direct connection is enabled for raw-transport XRay VLESS Reality, AmneziaWG, and WireGuard. Raw XRay JSON profiles are normalized to a loopback-only SOCKS inbound and routed through the bundled XRay runner and `tun2socks`. OpenVPN, Shadowsocks, and IKEv2 remain unavailable until their bundled isolated or privileged routing backends are integrated; `amn` refuses them instead of reporting a false VPN connection.

Amnezia full-access bundles and XRay share links can be imported and stored. Export them to a native protocol configuration before connecting.

The Cargo build builds AmneziaVPN recipe outputs and places `openvpn`, `tun2socks`, `amneziawg-go`, `amnezia-xray-runner`, `geoip.dat`, and `geosite.dat` under `libexec/amn` beside `amn`. AmneziaWG and WireGuard connections also require their platform tools (`awg`, `awg-quick`, `wg`, and `wg-quick`) in a root-owned bundle or system program directory. Raw XRay uses the bundled runner and `tun2socks` plus trusted `ip`, `setsid`, and `kill` tools.

Before changing an interface, `amn` requires root execution and validates the managed profile, command-line tools, DNS and firewall helpers, and the required kernel module or userspace backend. It executes a validated profile copy from a root-owned private runtime directory. Every connect and disconnect plan includes the opposite rollback action; failures restore the interface only when its current ownership still matches the selected profile.

Use `--dry-run` to inspect the exact external command without connecting:

```text
amn --dry-run connect
```

## AmneziaVPN TUI

Use `↑` and `↓` to select any connection, profile, server, settings, split-tunnel, backup, log, or diagnostic action. Press `Enter`, provide requested values inside the TUI, then press `Enter` again to run it.

- `PgUp` or `PgDn`: scroll action results
- `c`: connect the default profile
- `d`: disconnect
- `r`: reload saved state
- `q` or `Esc`: quit

## Servers

Save an SSH server that uses key or agent authentication:

```text
amn server add 203.0.113.10 --user root --identity ~/.ssh/id_ed25519
amn server list
amn server test SERVER_ID
amn server scan SERVER_ID
```

Password credentials are never accepted or saved. Server scanning reports Docker containers through SSH.

## DNS, routing, and safety

```text
amn settings set primary-dns 9.9.9.9
amn split-tunnel mode only-listed
amn split-tunnel add route 10.0.0.0/8
amn split-tunnel list
```

Routing settings are preserved for the bundled privileged backend. WireGuard and AmneziaWG retain routing rules from their native profiles.

Kill-switch settings are preserved, but connection is refused while either kill switch is enabled because this version has no native firewall backend. This prevents an unprotected connection from being reported as protected.

Imported profiles, saved state, and backups are written with owner-only permissions on Unix systems. OpenVPN profiles containing executable hook directives are rejected.

## Backup and logs

```text
amn backup create ~/amnezia-backup.json
amn backup restore ~/amnezia-backup.json
amn logs show
amn logs export ~/amnezia-connection.log
amn logs clear
```

Run `amn doctor` to check tools required by imported profiles.
