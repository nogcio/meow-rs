# Explicit domain-addressed XUDP API

This fork adds an opt-in library API for clients that must preserve a DNS name in
every Mux.Cool UDP frame without resolving it locally. The concrete consumer is
NetworkManager Tunnel's supplied-socket VLESS engine. No protocol daemon, resolver,
dependency, unsafe code or change to the existing metadata-based UDP fallback path
is introduced.

## Addresses and operations

`meow_common::PacketAddr` represents an IP socket address or a DNS hostname/port.
Debug redacts identifying values. `PacketAddr::domain` checks an ASCII hostname
(1..=253 bytes, labels 1..=63 bytes, letters/digits/hyphens, no IP literals)
and a nonzero port. The enum remains constructible, so domain writers independently
revalidate input before writing. Invalid input has a static error, not raw names.

Two default methods extend `ProxyPacketConn` without requiring changes to existing
implementations:

- `write_packet_to` forwards IPs to the old method; unsupported domain writes return
  `NotSupported`, without DNS or fallback.
- `read_packet_from` wraps the old IP/sentinel result by default. A typed Mux.Cool
  implementation preserves IP, domain and absent wire source metadata separately.
  It never converts an unrelated domain source to the bound-IP sentinel.

`VlessAdapter::dial_xudp_domain` explicitly opens a domain stream only when UDP-enabled
Mux.Cool is configured. Missing/wrong mux, malformed names and invalid ports reject
before dialing. The configured dialer and existing session setup deadlines remain
authoritative. No plain VLESS UDP substitution occurs through this method.

The returned Mux.Cool connection writes a domain in every `Keep+Data` frame using
the existing encoder. Empty or over-8192-byte domain datagrams reject before writes;
a subsequent valid packet remains usable. IP writes retain the existing encoding
and behavior. Legacy reads retain their original lossy projection, without applying
the typed reader's hostname validation to existing consumers.

Reads use one existing event queue and cancellation-safe session reader. An absent
address is `None`; domain bytes must be valid supported hostname syntax or the typed
read fails with a redacted error. A malformed source consumes that packet, not a
successful delivery. A caller must not concurrently mix the legacy and typed read
APIs: both consume the same queue. Dropping a pending read releases its receiver
lock; dropping the connection retains existing stream/End-frame cleanup semantics.

## Consumer responsibility

Use the typed read/write pair for domain XUDP; the old `write_packet` still accepts
only IP addresses. Calling it with a placeholder does not preserve a domain.
The new API retains rather than authenticates source metadata. An XUDP peer may
reply with a resolved IP instead of the requested name. The client must explicitly
define which source/port changes are acceptable for its destination-bound flow;
do not silently label an unrelated address as the requested hostname. These values
never authorize direct sockets or host routes.

The existing `dial_udp` path continues to decline domain Mux.Cool metadata, preserving
compatibility with legacy callers that cannot write typed destinations. No existing
application is automatically opted into this API.

## Verification

```sh
cargo test --locked -p meow-common --lib conn::tests
cargo test --locked -p meow-proxy --no-default-features \
  --features vless,vless-vision,mux --lib mux::
```

Typed contract tests use the production Mux.Cool encoder/decoder over bounded duplex
peers. They check initial and per-packet domains, distinct domain/IP/absent sources,
legacy projection, invalid input/size rejection without writes, cancelled-read reuse
and continued traffic. Existing IP, framing, cancellation and cleanup tests remain.
These are library contracts, not real-peer or deployed NetworkManager acceptance.
The consuming project must separately verify its source policy and real-peer wire
interoperability before changing its immutable production dependency pin.
