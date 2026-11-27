//! TCP connect probe bound to one interface.
//!
//! A completed handshake and a refused connection (RST) both prove that the
//! host answered through this interface, so both count as `ok`.

use super::{err_code, ms};
use crate::model::ProbeResult;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpSocket;
use tokio::time::{Instant, timeout};

/// Connects to `dst` through `iface` within `timeout`; RTT is the handshake time.
pub async fn connect(iface: &str, dst: SocketAddr, timeout_d: Duration) -> ProbeResult {
    let sock = match bound_socket(iface, &dst) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let start = Instant::now();
    match timeout(timeout_d, sock.connect(dst)).await {
        Ok(Ok(_stream)) => ProbeResult::ok(ms(start.elapsed())),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            ProbeResult::ok(ms(start.elapsed()))
        }
        Ok(Err(e)) => ProbeResult::fail(err_code(&e, "connect_failed")),
        Err(_) => ProbeResult::fail("timeout"),
    }
}

/// Creates a TCP socket of the right family bound to `iface`.
pub(crate) fn bound_socket(iface: &str, dst: &SocketAddr) -> Result<TcpSocket, ProbeResult> {
    let sock = if dst.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| ProbeResult::fail(err_code(&e, "socket_failed")))?;
    sock.bind_device(Some(iface.as_bytes()))
        .map_err(|e| ProbeResult::fail(err_code(&e, "bind_failed")))?;
    Ok(sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_device_fails_cleanly() {
        let r = connect(
            "nosuchif0",
            "127.0.0.1:9".parse().unwrap(),
            Duration::from_millis(200),
        )
        .await;
        assert!(!r.ok);
        assert_eq!(r.err.as_deref(), Some("no_device"));
    }

    #[tokio::test]
    #[ignore = "needs real network on wlo1"]
    async fn real_connect() {
        let r = connect(
            "wlo1",
            "1.1.1.1:443".parse().unwrap(),
            Duration::from_secs(1),
        )
        .await;
        println!("tcp 1.1.1.1:443 {r:?}");
        assert!(r.ok);
        let r = connect(
            "wlo1",
            "192.0.2.1:443".parse().unwrap(),
            Duration::from_millis(300),
        )
        .await;
        println!("tcp 192.0.2.1:443 {r:?}");
        assert_eq!(r.err.as_deref(), Some("timeout"));
    }
}
