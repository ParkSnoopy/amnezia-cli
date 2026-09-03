# Context

## Product boundary

AmneziaVPN CLI is a Linux-only, CLI-only Go application whose executable is named `amn`. It supports exactly XRay, WireGuard, and AmneziaWG. It accepts native XRay JSON and native WireGuard-family INI configuration; it never requires an application-specific profile format.

## Network model

Every protocol ultimately exposes `amn0`. The supervisor first creates an owner-derived, unpredictable TUN name and keeps its file descriptor. XRay requires the supplied descriptor's live name to match its configuration, so its verified staging interface is renamed to `amn0` before XRay starts; WireGuard-family interfaces are renamed after UAPI configuration. Each source-built backend receives the exact open descriptor. The descriptor and kernel index are the ownership identity, and teardown closes the owned descriptor rather than deleting a mutable name. IPv4 traffic selection is always the mathematical complement of IPv4 user exclusions. Automatic backend and SSH safety paths are not folded into that complement: each receives one exact `/32` route through its pre-tunnel gateway and interface. IPv6 addresses, endpoints, exclusions, gateways, and managed routes are unsupported. There is no kill switch, firewall mutation, policy-routing table, transparent-proxy flag, or local proxy exposed to the user.

XRay uses its native TUN inbound over the supervisor-created descriptor; the supervisor applies its gateway addresses and ordinary main-table routes because XRay deliberately leaves externally supplied interfaces unconfigured. Fixed XRay proxy endpoints are resolved before route mutation, replaced with the selected immutable IPv4 address in the managed native configuration, and given an original-path host route; an implicit TLS server name is preserved when address pinning would otherwise replace it. WireGuard and AmneziaWG use source-built userspace backends, their native UAPI sockets, interface addresses, and the same route mechanism. With no user exclusions their peer AllowedIPs and managed tunnel routes are exactly `0.0.0.0/0`; endpoint protection is a separate host route. Link, address, rename, and route mutations use the Linux route-netlink API directly; no host `ip` executable is resolved.

## Lifecycle

The public command launches an internal supervisor. Before the first network mutation, the supervisor writes a private durable recovery journal containing only ownership and process/interface intent—never configuration or secrets. Original-path route identities are recorded as unapplied before mutation and marked applied only after a successful kernel acknowledgement is durably recorded. Cleanup never deletes an unapplied route; if an ambiguous operation leaves its exact identity present, recovery evidence is retained rather than risking a foreign route. The supervisor owns the backend process and gives it a parent-death signal. It creates the interface and reports readiness. After displaying the prompt, the public command arms one authoritative ten-second supervisor deadline and waits for an explicit newline confirmation. Until confirmation, no durable active connection exists. Timeout, caller death, signal, setup error, or failed confirmation reports rollback only after routes, the backend, and the owned interface are verified absent; otherwise the recovery journal and runtime evidence remain.

Confirmation is handled by the supervisor, which atomically persists exact process and interface identity before acknowledging success. Disconnect verifies the supervisor identity and sends a private control request. Foreign processes or a replaced `amn0` are never signalled or deleted.

## Source trust

Release runtime programs are built from the pinned `thirdparty/xray-core`, `thirdparty/wireguard-go`, and `thirdparty/amneziawg-go` source trees. No downloaded executable is accepted. Adding or replacing a source submodule requires explicit user approval.

Runtime engines are resolved only from `libexec/amn/` relative to the running `amn` executable, including the portable and installed `../libexec/amn/` layouts. Runtime validation and startup receive an empty `PATH`; a missing bundled engine never falls through to a system installation. A portable user-built bundle is accepted when `amn` and its engines share one owner, executable files are not group/world-writable, and the path is symlink-free through directories owned by that bundle owner or root. Installed root-owned bundles satisfy the same rule. Each validated engine inode remains pinned by an open descriptor and is executed through that descriptor, preventing a path replacement between validation and privileged startup.

The project build is generated with CMake and executed with Ninja. Makefiles are not part of the build contract.

## Private data

`/run/amn` and `/var/lib/amn` are root-only. Native configuration is copied only into private runtime storage while a connection is active or recovery is still required. Logs and state never include private keys, tokens, or complete configuration content. State keeps only the exact process, interface, tunnel-route, and original-path host-route identity needed for verified cleanup; the latter necessarily includes its resolved IPv4 destination.
