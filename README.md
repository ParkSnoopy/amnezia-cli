# Amnezia TUI

Amnezia TUI is a terminal client for managing and connecting Amnezia-compatible VPN profiles without Qt or a graphical desktop.

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

Direct connection is enabled for WireGuard and AmneziaWG. OpenVPN, XRay, Shadowsocks, and IKEv2 remain unavailable until their bundled isolated or privileged routing backends are integrated; `amn` refuses them instead of executing untrusted profile directives or reporting a false VPN connection.

Amnezia full-access bundles and XRay share links can be imported and stored. Export them to a native protocol configuration before connecting.

The matching protocol helper must be bundled under `libexec/amn`, supplied through `AMN_LIBEXEC`, or available in `PATH`: `openvpn`, `wg-quick`, `awg-quick`, `xray`, `tun2socks`, `sslocal`, or `swanctl`. The `amn` frontend itself has no Qt dependency.

Use `--dry-run` to inspect the exact external command without connecting:

```text
amn --dry-run connect
```

## Terminal dashboard

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
