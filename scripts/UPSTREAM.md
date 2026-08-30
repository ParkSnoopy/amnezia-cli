# Upstream server fixtures

The files beneath `server/` are byte-identical copies of the Linux server fixtures selected from the pinned Amnezia client submodule. They cover only AmneziaWG, XRay, WireGuard, OpenVPN, and IPsec/IKEv2, plus the shared host scripts required to provision those endpoints.

`UPSTREAM_MANIFEST.txt` records the upstream tag, commit, source root, license, and SHA-256 checksum of every copied file. Local provisioning behavior belongs in Rust or separate project-owned files; do not edit copied fixtures in place.

## Updating the submodule

After updating `amnezia-client`, compare the selected files manually before copying anything:

```text
diff -ru \
  amnezia-client/client/server_scripts/awg \
  scripts/server/awg

diff -ru \
  amnezia-client/client/server_scripts/xray \
  scripts/server/xray
```

Repeat the comparison for `awg_legacy`, `wireguard`, `openvpn`, `ipsec`, and each shared script listed in the manifest. Review upstream changes, copy the accepted files, then regenerate every checksum and update the pinned tag and commit. Build validation rejects missing, extra, or modified copied files.
