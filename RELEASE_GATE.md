# Release gate

A release is ready only when every applicable check succeeds.

## Build provenance

- `amn` is built from this Go module.
- `xray`, `wireguard-go`, and `amneziawg-go` are built from the pinned source submodules.
- CMake generates the build and Ninja executes it; no Makefile is used.
- The bundle contains no downloaded or host-copied runtime executable.
- Runtime engines resolve only from executable-relative `libexec/amn` layouts; validation and backend processes receive no system search path.
- Submodule revisions and working trees are recorded and clean.
- `amn` and each privileged runtime have the same owner and are not group/world-writable; symlinks are rejected, and ancestor directories are owned by root or the bundle owner without unsafe write access.
- Runtime validation pins the accepted inode by descriptor, and validation/backend execution uses that descriptor rather than reopening a mutable path.

## Automated behavior

- Route-complement tests cover the documented `192.168.0.0/16` example, overlap, duplicates, and IPv4 full-family exclusion; IPv6 exclusions are rejected.
- Native WireGuard-family parsing rejects unknown or unsafe directives and never logs secrets.
- WireGuard-family configurations with no user exclusions emit exactly one `0.0.0.0/0` AllowedIP and one tunnel default route; resolved peer endpoints use separately owned original-path host routes.
- XRay preparation preserves upstream outbounds while replacing only the managed TUN inbound, resolves and pins fixed proxy endpoints before route mutation, and installs original-path host routes before tunnel routes.
- The supervisor pre-creates an owner-derived TUN, passes its open descriptor to every backend, and renames the unpredictable staging interface only while its kernel index remains unchanged; XRay is started after its name becomes `amn0`, while WireGuard-family backends are renamed after configuration.
- The ten-second confirmation deadline is armed only after the prompt is displayed; timeout and caller loss report success only after teardown postconditions hold.
- A recovery journal exists before mutation; active connection state appears only after confirmation.
- Original-path routes have connection-derived identities and durable unapplied/applied state; an `EEXIST` race or ambiguous unacknowledged creation never authorizes deletion, and failed cleanup retains recovery evidence until backend, interface, and exact owned bypass-route absence are verified.
- A reported startup failure is acknowledged and allowed to finish cleanup without caller signalling; an exited zombie is not treated as a live owned process.
- Interface, address, rename, and route operations pass in an isolated user/network namespace through the in-process route-netlink implementation without a host `ip` dependency.
- Disconnect checks stored PID start time and interface index before mutation.
- `cmake -S . -B build -G Ninja`, `cmake --build build`, and `cmake --build build --target check` succeed.

## Privileged acceptance

On a disposable Linux host with `/dev/net/tun`, root access, and internet connectivity:

1. Connect each supported protocol using a real native configuration.
2. Verify `amn0` carries traffic without a proxy argument.
3. With no exclusions, verify WireGuard and AmneziaWG show one `0.0.0.0/0` AllowedIP and one tunnel default route, plus only precise endpoint/SSH host routes through the original network path.
4. Verify excluded CIDRs continue through the original route.
5. Verify IPv6 exclusions and WireGuard-family IPv6 interface addresses/endpoints are rejected.
6. Do not confirm; verify teardown after ten seconds and continued SSH access.
7. Confirm; verify state survives command exit and `amn status` reports active.
8. Disconnect; verify routes, `amn0`, backend processes, runtime configuration, and state are absent.
9. Replace or race the interface/process/route identity; verify cleanup refuses foreign resources.

Without these privileged checks, automated validation is complete but real VPN release readiness remains unverified.
