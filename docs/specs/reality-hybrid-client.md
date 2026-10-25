# Optional hybrid REALITY client exchange

The `nogcio` fork implements the existing
`RealityConfig.support_x25519_mlkem768` option. It is opt-in: `false` retains the
historical profile's X25519-only offer. No global default, profile name, daemon,
resolver, route owner or certificate-verification bypass is introduced.

## Wire and ownership contract

- When enabled, supported groups and key shares offer `X25519MLKEM768` (`0x11ec`)
  before `X25519` (`0x001d`), after any profile GREASE entry.
- The hybrid client share is the 1184-byte ML-KEM-768 encapsulation key followed
  by the same 32-byte ephemeral X25519 public key used by the standalone share
  and REALITY session-ID authentication. The complete ClientHello is sealed only
  after both shares and all profile extensions are encoded.
- A hybrid ServerHello contains a 1088-byte ciphertext and a 32-byte X25519 share.
  The TLS shared secret concatenates ML-KEM then X25519, using BoringSSL's safe
  ML-KEM API (`boring >=5.3`, `mlkem` feature). No ML-KEM primitive is implemented
  in this repository and no new TLS backend is introduced.
- Selecting a hybrid group that was not offered, malformed lengths, unknown groups,
  duplicate key-share extensions and low-order X25519 shares fail. A server may
  select the separately offered X25519 share; there is no automatic redial or
  post-authentication downgrade.
- The existing authenticated REALITY certificate/Finished checks, handshake deadline,
  bounded server flight and directional Vision raw bypass remain in force.
  The ML-KEM key belongs to one handshake and is dropped on completion/error/cancellation.

Hybrid support is an explicit overlay on the existing historical browser tables.
It preserves their extension/profile selection, SNI and ALPN behavior, but does not
claim to reproduce an exact contemporary Chrome/Firefox/Safari/iOS/Edge release.
The option does not enable PQ VLESS encryption or ML-DSA certificate verification.
HelloRetryRequest remains unsupported and errors; no retry strips the hybrid offer.

## Verification

Private tests cover emitted group/share ordering, shared X25519 authentication material,
profile/SNI/ALPN preservation, malformed offers, TLS shared-secret ordering, malformed and
unoffered peer shares, and classical selection from a hybrid offer.

The explicit peer regression uses synthetic credentials and Xray **26.10.21** on Linux
x86-64, never a personal endpoint. Its archive is
`https://github.com/XTLS/Xray-core/releases/download/v26.10.21/Xray-linux-64.zip`,
SHA-256 `0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978`.
The extracted binary must have SHA-256
`a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e`.
The runner does not download, install or execute an unpinned peer automatically.

```sh
cargo test --locked -p meow-transport --no-default-features --features tls,ws,reality --lib
python3 scripts/check_reality_peer.py --peer /path/to/verified/xray
```

The runner builds the regression and then invokes the test binary inside a bubblewrap
loopback-only network namespace. It needs Cargo, Python 3, bubblewrap, GNU timeout,
enabled unprivileged user namespaces and native BoringSSL build prerequisites. Missing
tools, a wrong peer hash, startup failure, timeout or skipped execution are not passes.
Only disposable synthetic fixture files are writable inside the namespace.

The peer test covers payloads for five profile labels, both plain VLESS and Vision;
wrong keys, short IDs, SNI and UUIDs must not reach the echo target. An additional
inner TLS 1.3 connection negotiates `h2` ALPN and verifies payload delivery plus
byte-for-byte raw TLS application records on the outer socket in **both directions**,
demonstrating Vision DIRECT rather than merely padded non-TLS forwarding. This is
not an HTTP/2 application conformance test. The ordinary test harness ignores this
opt-in peer test; the runner explicitly executes it and must report zero ignored tests.

This does not establish UDP/XUDP, all browser fingerprints, all peer versions,
performance, security certification or NetworkManager routing/DNS acceptance.
