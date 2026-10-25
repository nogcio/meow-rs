//! Bounded in-memory wire observation for the isolated Vision DIRECT fixture.
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Default)]
pub struct Capture {
    pub read: Arc<Mutex<Vec<u8>>>,
    pub written: Arc<Mutex<Vec<u8>>>,
}

fn append(capture: &Mutex<Vec<u8>>, bytes: &[u8]) {
    let mut buffer = capture.lock().unwrap();
    assert!(
        buffer.len() + bytes.len() <= 512 * 1024,
        "fixture capture exceeded bound"
    );
    buffer.extend_from_slice(bytes);
}

pub struct Recorded<T> {
    pub inner: T,
    pub capture: Capture,
}

impl<T: AsyncRead + Unpin> AsyncRead for Recorded<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        append(&self.capture.read, &buf.filled()[before..]);
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Recorded<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            append(&self.capture.written, &buf[..n]);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// An inner TLS application record must appear byte-for-byte on the outer wire.
/// Nested outer encryption or Vision framing alone cannot establish raw bypass.
pub fn assert_direct_record(inner: &Mutex<Vec<u8>>, outer: &Mutex<Vec<u8>>) {
    let inner = inner.lock().unwrap();
    let outer = outer.lock().unwrap();
    let mut offset = 0;
    while offset + 5 <= inner.len() {
        let length = usize::from(u16::from_be_bytes([inner[offset + 3], inner[offset + 4]]));
        let end = offset + 5 + length;
        assert!(end <= inner.len(), "truncated inner TLS record");
        if inner[offset] == 23
            && length > 1024
            && outer
                .windows(end - offset)
                .any(|bytes| bytes == &inner[offset..end])
        {
            return;
        }
        offset = end;
    }
    panic!("no raw inner TLS application record observed on outer wire");
}
