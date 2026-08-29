# AmneziaVPN TUI

AmneziaVPN TUI manages and connects VPN profiles from an interactive terminal dashboard or command-line interface.

## Usage

Open the interactive dashboard:

```text
amn --tui
```

Import a profile and connect:

```text
amn profile import ~/vpn/home.conf --name Home
amn profile list
amn connect
amn status
amn disconnect
```

Use `--dry-run` to preview a connection and its rollback without changing the network:

```text
amn --dry-run connect
```

## Supported profiles

- **AmneziaWG** through `awg-quick`
- **WireGuard** through `wg-quick`
- **OpenVPN** through the bundled OpenVPN client
- **XRay VLESS Reality** JSON using the `raw` transport
- **Shadowsocks** SIP002 `ss://` links and Shadowsocks XRay JSON
- **IKEv2** Amnezia JSON profiles containing a PKCS#12 client certificate
- **Amnezia connection keys and full-access bundles**, normalized to their selected supported protocol during import

OpenVPN profiles must be self-contained. Inline certificates and credentials are accepted; executable hooks, external credential files, background process directives, and interactive challenges are rejected.

XRay profiles are normalized to a loopback-only SOCKS inbound. IKEv2 requires `charon-cmd` from strongSwan. AmneziaWG and WireGuard require their matching quick-script and control tools. All connections require trusted `ip`, `setsid`, and process-control tools where applicable.

Before changing the network, `amn` validates the managed profile, root privileges, protocol programs, conditional DNS and firewall helpers, and kernel or userspace backends. Private profiles, state, backups, runtime configurations, and logs use owner-only permissions where supported.

## AmneziaVPN TUI

Use `↑` and `↓` to select connection, profile, server, settings, split-tunnel, backup, log, or diagnostic actions. Press `Enter`, provide the requested values inside the TUI, then press `Enter` again to run the action.

- `PgUp` or `PgDn`: scroll action results
- `c`: connect the default profile
- `d`: disconnect
- `r`: reload saved state
- `q` or `Esc`: quit

The TUI exposes the same operations as the command-line interface.
It uses the `FullColor` color profile with the `tokio-night` palette.

## Servers

Save an SSH server that uses key or agent authentication:

```text
amn server add 203.0.113.10 --user root --identity ~/.ssh/id_ed25519
amn server list
amn server test SERVER_ID
amn server scan SERVER_ID
```

Password credentials are never accepted or saved. Server scanning reports Docker containers through SSH.

## Routing

```text
amn split-tunnel mode only-listed
amn split-tunnel add route 10.0.0.0/8
amn split-tunnel list
```

OpenVPN and XRay support all-traffic, only-listed, and except-listed route modes. XRay split routes are IPv4 networks; OpenVPN accepts IPv4 and IPv6 networks. WireGuard and AmneziaWG use the routes in their native profiles.

Connection logging can be enabled or disabled:

```text
amn settings set logging true
```

## Backup and logs

```text
amn backup create ~/amnezia-backup.json
amn backup restore ~/amnezia-backup.json
amn logs show
amn logs export ~/amnezia-connection.log
amn logs clear
```

Run `amn doctor` to check the runtime tools required by every imported profile.
