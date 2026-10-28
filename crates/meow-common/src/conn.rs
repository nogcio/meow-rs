use crate::error::Result;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyConn: AsyncRead + AsyncWrite + Unpin + Send + Sync {
    fn remote_destination(&self) -> String {
        String::new()
    }
}

// Blanket impl for TcpStream etc.
impl ProxyConn for tokio::net::TcpStream {}

// Impl for Box<dyn ProxyConn>
impl<T: ProxyConn + ?Sized> ProxyConn for Box<T> {}

#[async_trait::async_trait]
pub trait ProxyPacketConn: Send + Sync {
    /// Read without erasing domain source metadata. None means the wire supplied
    /// no address, not an authenticated match with the caller's destination.
    /// Default adapters preserve their existing IP/sentinel result. Cancellation
    /// has the same ownership semantics as read_packet; no DNS is performed.
    async fn read_packet_from(&self, buf: &mut [u8]) -> Result<(usize, Option<PacketAddr>)> {
        self.read_packet(buf)
            .await
            .map(|(n, addr)| (n, Some(PacketAddr::Ip(addr))))
    }
    /// Send an explicit IP/domain destination without implicit DNS or fallback.
    /// Existing adapters retain their IP behavior and reject domains by default.
    /// Domain-capable adapters must validate before writing; dropping the future
    /// retains the underlying transport's existing incomplete-write semantics.
    async fn write_packet_to(&self, buf: &[u8], addr: &PacketAddr) -> Result<usize> {
        match addr {
            PacketAddr::Ip(addr) => self.write_packet(buf, addr).await,
            PacketAddr::Domain { .. } => Err(crate::MeowError::NotSupported(
                "Domain datagram addressing is unsupported".into(),
            )),
        }
    }
    /// Per-packet conns return the real wire source; bound conns may
    /// report the bound remote or an unspecified address when the
    /// underlying transport carries no source information. Consumers
    /// filtering on the source must skip the check for unspecified
    /// addresses or they would wedge bound conns.
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;
    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn close(&self) -> Result<()>;
}

/// Owned datagram wire address. A domain is not locally resolved or authority for
/// a physical socket. Debug never exposes identifying hostnames or IPs.
#[derive(Clone, PartialEq, Eq)]
pub enum PacketAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl std::fmt::Debug for PacketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PacketAddr([redacted])")
    }
}

impl PacketAddr {
    /// Check an ASCII DNS hostname (at most 253 bytes, labels 1..=63) and nonzero
    /// port without resolution. Names are preserved, not silently canonicalized.
    /// Invalid input returns a static redacted error; callers may also construct
    /// the enum directly, so transport writers must recheck domain variants.
    pub fn domain(host: &str, port: u16) -> Result<Self> {
        if port == 0
            || host.is_empty()
            || host.len() > 253
            || host.parse::<std::net::IpAddr>().is_ok()
            || !host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(crate::MeowError::NotSupported(
                "Invalid datagram domain destination".into(),
            ));
        }
        Ok(Self::Domain {
            host: host.into(),
            port,
        })
    }
}

pub struct UdpPacket {
    pub data: Bytes,
    pub addr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct IpOnly(AtomicUsize);
    #[async_trait::async_trait]
    impl ProxyPacketConn for IpOnly {
        async fn read_packet(&self, _: &mut [u8]) -> Result<(usize, SocketAddr)> {
            Ok((0, "0.0.0.0:0".parse().unwrap()))
        }
        async fn write_packet(&self, bytes: &[u8], _: &SocketAddr) -> Result<usize> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(bytes.len())
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn default_domain_write_rejects_without_changing_the_ip_adapter() {
        let conn = IpOnly(AtomicUsize::new(0));
        let domain = PacketAddr::domain("private-name.example", 443).unwrap();
        assert!(!format!("{domain:?}").contains("private-name"));
        assert!(conn.write_packet_to(b"payload", &domain).await.is_err());
        assert_eq!(conn.0.load(Ordering::SeqCst), 0);
        conn.write_packet_to(
            b"payload",
            &PacketAddr::Ip("192.0.2.1:443".parse().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(conn.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            conn.read_packet_from(&mut []).await.unwrap().1,
            Some(PacketAddr::Ip("0.0.0.0:0".parse().unwrap()))
        );
        for name in [
            "",
            "https://private-token",
            "127.0.0.1",
            ".example",
            "a..example",
            "-a.example",
        ] {
            let error = PacketAddr::domain(name, 443).unwrap_err();
            assert!(!error.to_string().contains("private-token"));
        }
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(maximum.len(), 253);
        assert!(PacketAddr::domain(&maximum, 443).is_ok());
        assert!(PacketAddr::domain(&(maximum + "a"), 443).is_err());
        assert!(PacketAddr::domain(&format!("{}.example", "a".repeat(64)), 443).is_err());
    }
}
