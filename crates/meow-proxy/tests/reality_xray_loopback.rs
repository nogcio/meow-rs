//! Explicit, pinned current-peer regression. Run only inside a loopback-only namespace.
#![cfg(feature = "vless-vision")]

#[path = "support/reality_capture.rs"]
mod capture;
use capture::{Capture, Recorded};

use meow_common::{Metadata, ProxyAdapter};
use meow_proxy::{dialer::TcpDialer, TransportChain, VlessAdapter, VlessFlow};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::Command,
    task::JoinSet,
    time::timeout,
};

const UUID: &str = "12345678-1234-4234-8234-123456789abc";
// Synthetic fixture only; no personal node is accepted by this test.
const PRIVATE_KEY: &str = "EB7kDvScuKqkcZ-g7QAwKthl-GyFJ7PtDrr8wV_QAE0";
const PUBLIC_KEY: &str = "8y8p8aO5lpROX8wIDsOzzLt13iQ-2DXZmTuqXjy0om0";
// Xray 26.10.21 Linux x86-64 binary from the SHA-256-verified release archive.
const PEER_SHA256: &str = "a27e3f95ab6ce270956d0cecd32eda4686a811afc71c64a6a734a3dede14883e";

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct FixtureDialer(u16, Option<Capture>);
#[async_trait::async_trait]
impl TcpDialer for FixtureDialer {
    async fn dial(
        &self,
        host: &str,
        port: u16,
        _: bool,
    ) -> std::io::Result<Box<dyn meow_transport::Stream>> {
        if host != "127.0.0.1" || port != self.0 {
            return Err(std::io::Error::other("unexpected fixture dial"));
        }
        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        if let Some(capture) = &self.1 {
            Ok(Box::new(Recorded {
                inner: stream,
                capture: capture.clone(),
            }))
        } else {
            Ok(Box::new(stream))
        }
    }
}

struct Echo {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Echo {
    async fn start() -> Self {
        Self::with_tls(None).await
    }

    async fn with_tls(tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        let task = tokio::spawn(async move {
            let mut children = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (stream, _) = incoming.unwrap();
                        counter.fetch_add(1, Ordering::SeqCst);
                        let tls = tls.clone();
                        children.spawn(async move {
                            let mut stream: Box<dyn meow_transport::Stream> = if let Some(tls) = tls {
                                match tls.accept(stream).await {
                                    Ok(stream) => Box::new(stream),
                                    Err(_) => return,
                                }
                            } else { Box::new(stream) };
                            let mut buffer = [0; 8192];
                            loop {
                                match stream.read(&mut buffer).await {
                                    Ok(0) | Err(_) => break,
                                    Ok(n) => if stream.write_all(&buffer[..n]).await.is_err() { break; },
                                }
                            }
                        });
                    }
                    _ = children.join_next(), if !children.is_empty() => {}
                }
            }
        });
        Self {
            address,
            accepted,
            task,
        }
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn adapter(port: u16, profile: &str, vision: bool, bad: &str) -> VlessAdapter {
    adapter_with_capture(port, profile, vision, bad, None)
}

fn adapter_with_capture(
    port: u16,
    profile: &str,
    vision: bool,
    bad: &str,
    capture: Option<Capture>,
) -> VlessAdapter {
    use base64::Engine;
    let mut public_key: [u8; 32] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(PUBLIC_KEY)
        .unwrap()
        .try_into()
        .unwrap();
    if bad == "key" {
        public_key = [1; 32];
    }
    let tls = TlsConfig {
        fingerprint: Some(profile.into()),
        reality: Some(RealityConfig {
            public_key,
            short_id: if bad == "short-id" { [0; 8] } else { [0xab; 8] },
            support_x25519_mlkem768: true,
        }),
        ..TlsConfig::new(if bad == "sni" {
            "wrong.example"
        } else {
            "peer.example"
        })
    };
    let mut chain = TransportChain::empty();
    chain.push(Box::new(TlsLayer::new(&tls).unwrap()));
    let mut uuid: [u8; 16] = hex::decode(UUID.replace('-', ""))
        .unwrap()
        .try_into()
        .unwrap();
    if bad == "credential" {
        uuid[15] ^= 1;
    }
    VlessAdapter::new(
        "synthetic",
        "127.0.0.1",
        port,
        uuid,
        vision.then_some(VlessFlow::XtlsRprxVision),
        false,
        chain,
        Arc::new(FixtureDialer(port, capture)),
    )
}

async fn round_trip(adapter: &VlessAdapter, target: SocketAddr) -> Result<(), String> {
    let metadata = Metadata {
        dst_ip: Some(target.ip()),
        dst_port: target.port(),
        ..Default::default()
    };
    let mut stream = adapter
        .dial_tcp(&metadata)
        .await
        .map_err(|e| e.to_string())?;
    let payload: Vec<u8> = (0..65549).map(|index| (index % 251) as u8).collect();
    stream
        .write_all(&payload)
        .await
        .map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())?;
    let mut response = vec![0; payload.len()];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| e.to_string())?;
    if response != payload {
        return Err("payload mismatch".into());
    }
    stream.shutdown().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires pinned Xray 26.10.21 and an explicitly isolated network namespace"]
async fn hybrid_reality_relays_payload_and_refuses_invalid_authentication() {
    assert_eq!(
        std::env::var("MEOW_ISOLATED_PEER_TEST").as_deref(),
        Ok("1"),
        "use the documented network-namespace invocation"
    );
    let binary = std::env::var_os("XRAY_BINARY").expect("XRAY_BINARY is required; never skip");
    let mut file = std::fs::File::open(&binary).unwrap();
    let mut digest = Sha256::new();
    let mut chunk = [0; 8192];
    loop {
        let count = file.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&chunk[..count]);
    }
    assert_eq!(
        hex::encode(digest.finalize()),
        PEER_SHA256,
        "unreviewed peer binary"
    );
    let root = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["peer.example".into()]).unwrap();
    let port = free_port();
    let vision_port = free_port();
    let cover_port = free_port();
    let inbound = |port, vision| {
        json!({
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID, "flow": if vision {"xtls-rprx-vision"} else {""}}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                "target": format!("127.0.0.1:{cover_port}"), "serverNames": ["peer.example"],
                "privateKey": PRIVATE_KEY, "shortIds": ["abababababababab"]}}
        })
    };
    let config = json!({
        "log": {"loglevel": "warning"},
        "inbounds": [inbound(port, false), inbound(vision_port, true), {
            "listen": "127.0.0.1", "port": cover_port, "protocol": "vless",
            "settings": {"clients": [{"id": UUID}], "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {"certificates": [{
                "certificate": certificate.cert.pem().lines().collect::<Vec<_>>(),
                "key": certificate.key_pair.serialize_pem().lines().collect::<Vec<_>>()
            }]}}
        }],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]}}]
    });
    let path = root.path().join("fixture.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let log = std::fs::File::create(root.path().join("peer.log")).unwrap();
    let mut child = Command::new(binary)
        .args(["run", "-c"])
        .arg(path)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(8), async {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "fixture exited before readiness"
            );
            if TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_ok()
            {
                break;
            }
            tick.tick().await;
        }
    })
    .await
    .expect("peer readiness deadline");
    let echo = Echo::start().await;
    for profile in ["chrome", "firefox", "safari", "ios", "edge"] {
        for vision in [false, true] {
            let client = adapter(if vision { vision_port } else { port }, profile, vision, "");
            let result = timeout(Duration::from_secs(10), round_trip(&client, echo.address))
                .await
                .expect("valid payload deadline");
            assert!(
                result.is_ok(),
                "profile={profile} vision={vision}: {result:?}"
            );
        }
    }
    for bad in ["key", "short-id", "sni", "credential"] {
        let before = echo.accepted.load(Ordering::SeqCst);
        let client = adapter(port, "chrome", false, bad);
        let result = timeout(Duration::from_secs(10), round_trip(&client, echo.address))
            .await
            .expect("negative timeout is a failure, not an authentication refusal");
        assert!(result.is_err(), "invalid {bad} accepted");
        assert_eq!(
            echo.accepted.load(Ordering::SeqCst),
            before,
            "invalid {bad} reached target"
        );
    }
    // Exercise actual inner TLS 1.3, not only Vision's padded non-TLS path.
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.key_pair.serialize_der())
                .into(),
        )
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let tls_echo = Echo::with_tls(Some(tokio_rustls::TlsAcceptor::from(Arc::new(server)))).await;
    let wire = Capture::default();
    let inner = Capture::default();
    let client = adapter_with_capture(vision_port, "chrome", true, "", Some(wire.clone()));
    timeout(Duration::from_secs(10), async {
        let metadata = Metadata {
            dst_ip: Some(tls_echo.address.ip()),
            dst_port: tls_echo.address.port(),
            ..Default::default()
        };
        let tunnel = client.dial_tcp(&metadata).await.unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.cert.der().clone()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut tls = connector
            .connect(
                "peer.example".try_into().unwrap(),
                Recorded {
                    inner: tunnel,
                    capture: inner.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            tls.get_ref().1.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        let payload = vec![0x53; 65549];
        tls.write_all(&payload).await.unwrap();
        tls.flush().await.unwrap();
        let mut response = vec![0; payload.len()];
        tls.read_exact(&mut response).await.unwrap();
        assert_eq!(response, payload);
        tls.shutdown().await.unwrap();
    })
    .await
    .expect("Vision DIRECT deadline");
    capture::assert_direct_record(&inner.written, &wire.written);
    capture::assert_direct_record(&inner.read, &wire.read);
    child.start_kill().unwrap();
    timeout(Duration::from_secs(3), child.wait())
        .await
        .expect("peer teardown deadline")
        .unwrap();
}
