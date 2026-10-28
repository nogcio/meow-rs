//! Explicit synthetic-only domain XUDP probe for the loopback namespace harness.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use meow_common::PacketAddr;
use meow_proxy::{
    mux::{MuxOptions, Protocol},
    TransportChain, VlessAdapter, VlessFlow,
};
use meow_transport::tls::{RealityConfig, TlsConfig, TlsLayer};
use std::{net::SocketAddr, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("MEOW_ISOLATED_PEER_TEST").as_deref() != Ok("1") {
        return Err("Use the explicit isolated loopback harness".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 || !["xudp-domain", "vision-xudp-domain"].contains(&args[0].as_str()) {
        return Err("Expected a synthetic XUDP domain mode".into());
    }
    let vision = args[0].starts_with("vision");
    let endpoint = SocketAddr::from(([127, 0, 0, 1], if vision { 24449 } else { 24444 }));
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(std::env::var("MEOW_TEST_PUBLIC_KEY")?)?
        .try_into()
        .map_err(|_| "Invalid synthetic public key")?;
    let mut tls = TlsConfig::new("peer.example");
    tls.fingerprint = Some("chrome".into());
    tls.reality = Some(RealityConfig {
        public_key: public,
        short_id: [0xab; 8],
        support_x25519_mlkem768: true,
    });
    let mut chain = TransportChain::empty();
    chain.push(Box::new(TlsLayer::new(&tls)?));
    let credential: [u8; 16] = hex::decode("12345678123442348234123456789abc")?
        .try_into()
        .map_err(|_| "Invalid synthetic UUID")?;
    let adapter = VlessAdapter::new(
        "synthetic",
        "127.0.0.1",
        endpoint.port(),
        credential,
        vision.then_some(VlessFlow::XtlsRprxVision),
        true,
        chain,
        Arc::new(meow_proxy::dialer::DirectDialer),
    )
    .with_mux(MuxOptions {
        protocol: Protocol::MuxCool,
        max_connections: 1,
        min_streams: 1,
        max_streams: 1,
        padding: false,
        only_tcp: false,
    });
    tokio::time::timeout(Duration::from_secs(20), async {
        let connection = adapter
            .dial_xudp_domain("echo.fixture.invalid", 24445)
            .await?;
        let destination = PacketAddr::domain("echo.fixture.invalid", 24445)?;
        let expected_source = destination.clone();
        let mut buffer = vec![0; 8192];
        for size in [1, 1400, 8192] {
            let payload: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
            assert_eq!(
                connection.write_packet_to(&payload, &destination).await?,
                payload.len()
            );
            let (n, source) = connection.read_packet_from(&mut buffer).await?;
            println!(
                "Synthetic source kind: {}",
                match &source {
                    Some(PacketAddr::Ip(_)) => "ip",
                    Some(PacketAddr::Domain { .. }) => "domain",
                    None => "absent",
                }
            );
            if buffer[..n] != payload || source != Some(expected_source.clone()) {
                return Err("Domain XUDP payload or wire source mismatch".into());
            }
        }
        if connection
            .write_packet_to(&vec![0; 8193], &destination)
            .await
            .is_ok()
        {
            return Err("Oversized XUDP domain packet was accepted".into());
        }
        connection
            .write_packet_to(b"after-rejection", &destination)
            .await?;
        let (n, source) = connection.read_packet_from(&mut buffer).await?;
        if &buffer[..n] != b"after-rejection" || source != Some(expected_source) {
            return Err("Rejected packet corrupted the domain association".into());
        }
        drop(connection);
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    println!(
        "PASS synthetic {}: domain per-packet echo, exact typed source, payload rejection",
        args[0]
    );
    Ok(())
}
