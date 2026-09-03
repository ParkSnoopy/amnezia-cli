# AmneziaVPN CLI

AmneziaVPN CLI is a Linux command-line VPN client. Its executable is named `amn`, and it supports XRay, WireGuard, and AmneziaWG.

It accepts each protocol's native configuration file, creates a TUN interface, and routes traffic automatically. There is no proxy flag and no kill switch. Connections route all IPv4 traffic except the IPv4 CIDR ranges supplied with `--exclude`. IPv6 is not supported or routed through the VPN.

Without `--exclude`, WireGuard and AmneziaWG use the single native `0.0.0.0/0` AllowedIP and a single default route through `amn0`. The resolved VPN server receives one precise host route through the original network path so backend traffic cannot loop into its own tunnel. XRay upstream hostnames are likewise resolved once, pinned in the managed native configuration, and kept on the original path.

Keep the complete bundle together. `amn` loads its source-built protocol engines from `libexec/amn/` relative to its own executable; it never searches the system `PATH`. Portable bundles may remain owned by the user who built them, but `amn` and every protocol engine must have the same owner and must not be group- or world-writable. Copying only `amn` without the adjacent `libexec` tree produces a direct missing-runtime error.

## Connect

Run as root and provide an upstream-native configuration:

```console
sudo amn connect --protocol xray --config ./config.json --exclude 192.168.0.0/16
sudo amn connect --protocol wireguard --config ./wg.conf --exclude 192.168.0.0/16
sudo amn connect --protocol amneziawg --config ./awg.conf --exclude 192.168.0.0/16
```

After the interface is ready, press Enter within ten seconds to keep it. If Enter is not pressed, `amn` removes the connection automatically. A confirmed connection continues after the command exits.

The current SSH client address receives the same precise original-path protection when `SSH_CONNECTION` is present, protecting the administration session that launched the command.

## Other commands

```console
sudo amn status
sudo amn disconnect
amn routes --exclude 192.168.0.0/16
amn version
```

`routes` prints the exact IPv4 CIDR complement used for route-all-except behavior. IPv6 CIDRs are rejected.

Only one connection is active at a time. Runtime files and connection state are private to root.
