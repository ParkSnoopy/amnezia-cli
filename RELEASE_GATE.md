# Release gate

A release is ready only when every applicable check succeeds.

## Build provenance

- `amn` is built from this Go module.
- `xray`, `wireguard-go`, and `amneziawg-go` are built from the pinned source submodules.
- The bundle contains no downloaded or host-copied runtime executable.
- Submodule revisions and working trees are recorded and clean.
- Privileged runtime files and every ancestor directory are root-owned and not group/world-writable; bundled runtime symlinks are rejected.

## Automated behavior

- Route-complement tests cover the documented `192.168.0.0/16` example, overlap, duplicates, IPv4, IPv6, and full-family exclusion.
- Native WireGuard-family parsing rejects unknown or unsafe directives and never logs secrets.
- XRay preparation preserves upstream outbounds while replacing only the managed TUN inbound.
- The supervisor pre-creates an owner-derived TUN, passes its open descriptor to every backend, and renames the unpredictable staging interface only while its kernel index remains unchanged; XRay is started after its name becomes `amn0`, while WireGuard-family backends are renamed after configuration.
- The ten-second confirmation deadline is armed only after the prompt is displayed; timeout and caller loss report success only after teardown postconditions hold.
- A recovery journal exists before mutation; active connection state appears only after confirmation.
- Failed cleanup retains recovery evidence until backend and interface absence are verified.
- Disconnect checks stored PID start time and interface index before mutation.
- `go test ./...`, `go vet ./...`, and the source bundle build succeed.

## Privileged acceptance

On a disposable Linux host with `/dev/net/tun`, root access, and internet connectivity:

1. Connect each supported protocol using a real native configuration.
2. Verify `amn0` carries traffic without a proxy argument.
3. Verify excluded CIDRs continue through the original route.
4. Do not confirm; verify teardown after ten seconds and continued SSH access.
5. Confirm; verify state survives command exit and `amn status` reports active.
6. Disconnect; verify routes, `amn0`, backend processes, runtime configuration, and state are absent.
7. Replace or race the interface/process identity; verify cleanup refuses foreign resources.

Without these privileged checks, automated validation is complete but real VPN release readiness remains unverified.
