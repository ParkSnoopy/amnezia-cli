# amn

`amn` is a Linux command-line VPN client for XRay, WireGuard, and AmneziaWG.

It accepts each protocol's native configuration file, creates a TUN interface, and routes traffic automatically. There is no proxy flag and no kill switch. Connections route all IPv4 and IPv6 traffic except the CIDR ranges supplied with `--exclude`.

## Connect

Run as root and provide an upstream-native configuration:

```console
sudo amn connect --protocol xray --config ./config.json --exclude 192.168.0.0/16
sudo amn connect --protocol wireguard --config ./wg.conf --exclude 192.168.0.0/16
sudo amn connect --protocol amneziawg --config ./awg.conf --exclude 192.168.0.0/16
```

After the interface is ready, press Enter within ten seconds to keep it. If Enter is not pressed, `amn` removes the connection automatically. A confirmed connection continues after the command exits.

The current SSH client address is excluded automatically when `SSH_CONNECTION` is present, protecting the administration session that launched the command.

## Other commands

```console
sudo amn status
sudo amn disconnect
amn routes --exclude 192.168.0.0/16
amn version
```

`routes` prints the exact CIDR complement used for route-all-except behavior.

Only one connection is active at a time. Runtime files and connection state are private to root.
