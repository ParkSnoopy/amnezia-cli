# AmneziaVPN TUI

AmneziaVPN TUI manages and connects VPN profiles from an interactive terminal dashboard or command-line interface.

## Usage

Install `amn` and its bundled programs under `/usr/local`:

```text
sudo ./amn init
```

This installs the command at `/usr/local/bin/amn` and its bundled programs at `/usr/local/libexec/amn`. Run `init` from the portable bundle so `amn` can find the bundled programs beside the running binary.

Open the interactive dashboard:

```text
amn --tui
```

Import a profile and connect:

```text
amn profile import ~/vpn/home.conf --name Home
amn profile list
amn profile show 1
amn connect 1
amn status
amn reconnect
amn disconnect
```

Profile commands use the number shown by `amn profile list`. Numbering starts at `1`.

Use `--dry-run` to preview a connection and its rollback without changing the network:

```text
amn --dry-run connect
```

## Supported profiles

- **AmneziaWG** through `awg-quick`
- **WireGuard** through `wg-quick`
- **OpenVPN** through the bundled OpenVPN client
- **XRay** profiles supported by the upstream Amnezia Linux client source branch
- **Amnezia connection keys and full-access bundles**, normalized to their selected supported protocol during import

OpenVPN profiles must be self-contained. Inline certificates and credentials are accepted; executable hooks, external credential files, background process directives, and interactive challenges are rejected.

XRay profiles are normalized to a loopback-only SOCKS inbound. AmneziaWG and WireGuard require their matching quick-script and control tools. All connections require trusted `ip`, `setsid`, and process-control tools where applicable.

Before changing the network, `amn` validates the managed profile, root privileges, protocol programs, its bundled DNS helper, conditional firewall helpers, and kernel or userspace backends. Private profiles, state, backups, runtime configurations, and logs use owner-only permissions where supported.

## AmneziaVPN TUI

Use `↑` and `↓` to select connection, profile, settings, split-tunnel, backup, log, or diagnostic actions. Press `Enter` to open the action's popup or selectable list. Profile choices use the displayed profile number and settings use value-specific editors; DNS servers are entered one address per line and validated before saving.

- `PgUp` or `PgDn`: scroll action results
- `Ins` or `Del`: add or remove a row in a multi-value editor
- `c`: connect the default profile
- `d`: disconnect
- `r`: reload saved state
- `q` or `Esc`: quit

The TUI exposes the same operations as the command-line interface. Structured results are shown as indented entries instead of raw JSON.

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
amn settings set dns-servers 1.1.1.1,1.0.0.1
```

The DNS list is applied transactionally while a VPN connection is active and the prior resolver contents are restored on disconnect. `amn` refuses rollback if another program changes the resolver during the connection. `status` also reports received and transmitted bytes when the active tunnel exposes Linux interface counters.

## Backup and logs

```text
amn backup create ~/amnezia-backup.json
amn backup restore ~/amnezia-backup.json
amn logs show
amn logs export ~/amnezia-connection.log
amn logs clear
```

Restore accepts both `amn` backups and partial AmneziaVPN settings backups. Every supplied field replaces the corresponding overall setting: a supplied server list replaces the installed profile list, while omitted settings remain unchanged.

Run `amn doctor` to check the runtime tools required by every imported profile.

The complete portable build is placed in `target/bundle/`. Keep `amn` and its `libexec/amn/` directory together when copying it to another Linux system.
