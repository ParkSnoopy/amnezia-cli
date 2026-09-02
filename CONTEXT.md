# Context

## Product boundary

`amn` is a Linux-only, CLI-only Go application. It supports exactly XRay, WireGuard, and AmneziaWG. It accepts native XRay JSON and native WireGuard-family INI configuration; it never requires an application-specific profile format.

## Network model

Every protocol ultimately exposes `amn0`. The supervisor first creates an owner-derived, unpredictable TUN name and keeps its file descriptor. XRay requires the supplied descriptor's live name to match its configuration, so its verified staging interface is renamed to `amn0` before XRay starts; WireGuard-family interfaces are renamed after UAPI configuration. Each source-built backend receives the exact open descriptor. The descriptor and kernel index are the ownership identity, and teardown closes the owned descriptor rather than deleting a mutable name. Traffic selection is always the mathematical complement of user exclusions. There is no kill switch, firewall mutation, policy-routing table, transparent-proxy flag, or local proxy exposed to the user.

XRay uses its native TUN inbound over the supervisor-created descriptor; the supervisor applies its gateway addresses and ordinary main-table routes because XRay deliberately leaves externally supplied interfaces unconfigured. WireGuard and AmneziaWG use source-built userspace backends, their native UAPI sockets, interface addresses, and the same route mechanism. Peer endpoints and the current SSH client are excluded to prevent routing loops and administration loss.

## Lifecycle

The public command launches an internal supervisor. Before the first network mutation, the supervisor writes a private durable recovery journal containing only ownership and process/interface intent—never configuration or secrets. The supervisor owns the backend process and gives it a parent-death signal. It creates the interface and reports readiness. After displaying the prompt, the public command arms one authoritative ten-second supervisor deadline and waits for an explicit newline confirmation. Until confirmation, no durable active connection exists. Timeout, caller death, signal, setup error, or failed confirmation reports rollback only after routes, the backend, and the owned interface are verified absent; otherwise the recovery journal and runtime evidence remain.

Confirmation is handled by the supervisor, which atomically persists exact process and interface identity before acknowledging success. Disconnect verifies the supervisor identity and sends a private control request. Foreign processes or a replaced `amn0` are never signalled or deleted.

## Source trust

Release runtime programs are built from the pinned `thirdparty/xray-core`, `thirdparty/wireguard-go`, and `thirdparty/amneziawg-go` source trees. No downloaded executable is accepted. Adding or replacing a source submodule requires explicit user approval.

## Private data

`/run/amn` and `/var/lib/amn` are root-only. Native configuration is copied only into private runtime storage while a connection is active or recovery is still required. Logs and state must never include private keys, tokens, endpoints, or complete configuration content.
