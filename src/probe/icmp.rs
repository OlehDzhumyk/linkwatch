//! Unprivileged ICMP echo over `SOCK_DGRAM`/`IPPROTO_ICMP` ("ping sockets").
//!
//! Needs the process group inside `net.ipv4.ping_group_range`; otherwise the
//! socket call fails with EACCES and the probe reports `"permission"`.
//! On ping sockets the kernel sets the ICMP identifier and filters replies by
//! it; replies arrive without the IP header. We still verify type, sequence
//! and a random payload token, so foreign or duplicate replies are ignored.
//!
//! [`probe_ttl`] sends one echo with a small TTL and reads the ICMP "time
//! exceeded" from the socket error queue (`IP_RECVERR` + `MSG_ERRQUEUE`).
//! This works unprivileged because the kernel delivers ICMP errors that quote
//! our echo request to the ping socket that sent it.

use super::{err_code, ms, random_bytes};
use crate::model::ProbeResult;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::io::Interest;
use tokio::time::{Instant, timeout_at};

const ICMP_ECHO_REPLY: u8 = 0;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_TIME_EXCEEDED: u8 = 11;
/// `SO_EE_ORIGIN_ICMP` from `<linux/errqueue.h>`.
const SO_EE_ORIGIN_ICMP: u8 = 2;
const TOKEN_LEN: usize = 16;
const HDR_LEN: usize = 8;

/// Sends one ICMP echo to `dst` through `iface` and waits up to `timeout`.
pub async fn ping(iface: &str, dst: Ipv4Addr, timeout: Duration) -> ProbeResult {
    let deadline = Instant::now() + timeout;
    let sock = match open(iface) {
        Ok(s) => s,
        Err(code) => return ProbeResult::fail(code),
    };
    // Connecting lets the kernel report hard ICMP errors (host unreachable)
    // as a recv error instead of only a timeout.
    if let Err(e) = sock.connect(&SockAddr::from(SocketAddrV4::new(dst, 0))) {
        return ProbeResult::fail(err_code(&e, "connect_failed"));
    }
    let std_sock: std::net::UdpSocket = sock.into();
    let sock = match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(s) => s,
        Err(e) => return ProbeResult::fail(err_code(&e, "socket_failed")),
    };
    let token = random_bytes();
    let seq = u16::from_be_bytes([token[0], token[1]]);
    let pkt = echo_request(seq, &token);

    let start = Instant::now();
    match timeout_at(deadline, sock.send(&pkt)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return ProbeResult::fail(err_code(&e, "send_failed")),
        Err(_) => return ProbeResult::fail("timeout"),
    }
    let mut buf = [0u8; 256];
    loop {
        match timeout_at(deadline, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                if is_our_reply(buf.get(..n).unwrap_or_default(), seq, &token) {
                    return ProbeResult::ok(ms(start.elapsed()));
                }
            }
            Ok(Err(e)) => return ProbeResult::fail(err_code(&e, "recv_failed")),
            Err(_) => return ProbeResult::fail("timeout"),
        }
    }
}

/// Sends one echo with IP TTL `ttl` and returns the address that answered:
/// the router that sent "time exceeded", or `dst` itself on an echo reply.
/// `None` on timeout or on any socket error (documented best effort).
pub async fn probe_ttl(iface: &str, dst: Ipv4Addr, ttl: u8, timeout: Duration) -> Option<Ipv4Addr> {
    use nix::sys::socket::{MsgFlags, recv, setsockopt, sockopt};
    let deadline = Instant::now() + timeout;
    let sock = open(iface).ok()?;
    sock.set_ttl_v4(u32::from(ttl.max(1))).ok()?;
    setsockopt(&sock, sockopt::Ipv4RecvErr, &true).ok()?;
    let token = random_bytes();
    let seq = u16::from_be_bytes([token[0], token[1]]);
    let pkt = echo_request(seq, &token);
    let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(dst, 0)));
    sock.send_to(&pkt, &to).ok()?;
    // A tokio UdpSocket owns the ping socket safely and gives readiness (incl. EPOLLERR).
    let std_sock: std::net::UdpSocket = sock.into();
    let afd = tokio::net::UdpSocket::from_std(std_sock).ok()?;
    let fd = afd.as_raw_fd();

    let mut buf = [0u8; 256];
    loop {
        timeout_at(deadline, afd.ready(Interest::READABLE | Interest::ERROR))
            .await
            .ok()?
            .ok()?;
        // Error queue first: a pending error would also fail a plain recv.
        while let Some(msg) = recv_errqueue(fd) {
            let quoted_seq = msg.data.get(6..8).map(|b| u16::from_be_bytes([b[0], b[1]]));
            let ours = quoted_seq.is_none_or(|s| s == seq);
            if ours
                && msg.origin == SO_EE_ORIGIN_ICMP
                && msg.icmp_type == ICMP_TIME_EXCEEDED
                && let Some(a) = msg.offender
            {
                return Some(a);
            }
        }
        // Bounded: a socket that keeps returning errors must not spin this task.
        for _ in 0..64 {
            match recv(fd, &mut buf, MsgFlags::MSG_DONTWAIT) {
                Ok(n) => {
                    if is_our_reply(&buf[..n.min(buf.len())], seq, &token) {
                        return Some(dst);
                    }
                }
                Err(nix::errno::Errno::EAGAIN) => break,
                // Pending socket error (already handled via the queue): retry.
                Err(_) => continue,
            }
        }
        // Both queues drained to EAGAIN: clear readiness and wait for the next event.
        let _ = afd.try_io(Interest::READABLE | Interest::ERROR, || Err::<(), _>(std::io::ErrorKind::WouldBlock.into()));
    }
}

/// Opens a non-blocking ping socket bound to `iface`.
fn open(iface: &str) -> Result<Socket, &'static str> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
        .map_err(|e| err_code(&e, "socket_failed"))?;
    s.set_nonblocking(true)
        .map_err(|e| err_code(&e, "socket_failed"))?;
    s.bind_device(Some(iface.as_bytes()))
        .map_err(|e| err_code(&e, "bind_failed"))?;
    Ok(s)
}

/// Echo request: header (identifier left 0, the kernel sets it) + token.
fn echo_request(seq: u16, token: &[u8; TOKEN_LEN]) -> [u8; HDR_LEN + TOKEN_LEN] {
    let mut p = [0u8; HDR_LEN + TOKEN_LEN];
    p[0] = ICMP_ECHO_REQUEST;
    p[6..8].copy_from_slice(&seq.to_be_bytes());
    p[HDR_LEN..].copy_from_slice(token);
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

/// RFC 1071 internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for ch in data.chunks(2) {
        let w = match ch {
            [a, b] => u16::from_be_bytes([*a, *b]),
            [a] => u16::from_be_bytes([*a, 0]),
            _ => 0,
        };
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// True when `pkt` (ICMP without IP header) is the echo reply to our request.
fn is_our_reply(pkt: &[u8], seq: u16, token: &[u8; TOKEN_LEN]) -> bool {
    pkt.len() >= HDR_LEN + TOKEN_LEN
        && pkt[0] == ICMP_ECHO_REPLY
        && pkt[1] == 0
        && pkt[6..8] == seq.to_be_bytes()
        && pkt[HDR_LEN..HDR_LEN + TOKEN_LEN] == token[..]
}

/// One message from the socket error queue.
#[derive(Debug, PartialEq)]
struct ErrQueueMsg {
    origin: u8,
    icmp_type: u8,
    offender: Option<Ipv4Addr>,
    /// Quoted original datagram (our ICMP header + payload).
    data: Vec<u8>,
}

/// Reads one message from the error queue; `None` when empty or on error.
fn recv_errqueue(fd: std::os::fd::RawFd) -> Option<ErrQueueMsg> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg};
    let mut data = [0u8; 256];
    let mut cmsg = nix::cmsg_space!(libc::sock_extended_err, libc::sockaddr_in);
    let mut iov = [std::io::IoSliceMut::new(&mut data)];
    let msg = recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg), MsgFlags::MSG_ERRQUEUE | MsgFlags::MSG_DONTWAIT).ok()?;
    let n = msg.bytes;
    let mut found = None;
    for c in msg.cmsgs().ok()? {
        if let ControlMessageOwned::Ipv4RecvErr(ee, addr) = c {
            let offender = addr
                .filter(|a| i32::from(a.sin_family) == libc::AF_INET)
                .map(|a| Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)));
            found = Some((ee.ee_origin, ee.ee_type, offender));
        }
    }
    let (origin, icmp_type, offender) = found?;
    Some(ErrQueueMsg { origin, icmp_type, offender, data: data[..n.min(256)].to_vec() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known_vector() {
        // Example from RFC 1071 discussions: words sum to 0xddf2 => !0xddf2.
        let d = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&d), !0xddf2u16);
        let token = [7u8; TOKEN_LEN];
        let p = echo_request(0x1234, &token);
        assert_eq!(checksum(&p), 0, "packet with checksum sums to zero");
    }

    #[test]
    fn reply_matching() {
        let token = [9u8; TOKEN_LEN];
        let mut r = echo_request(42, &token);
        r[0] = ICMP_ECHO_REPLY;
        assert!(is_our_reply(&r, 42, &token));
        assert!(!is_our_reply(&r, 43, &token));
        assert!(!is_our_reply(&r[..10], 42, &token));
        let mut other = r;
        other[HDR_LEN] ^= 1;
        assert!(!is_our_reply(&other, 42, &token));
        let req = echo_request(42, &token);
        assert!(!is_our_reply(&req, 42, &token));
        assert!(!is_our_reply(&[], 42, &token));
    }

    #[tokio::test]
    async fn missing_device_fails_cleanly() {
        let r = ping("nosuchif0", Ipv4Addr::LOCALHOST, Duration::from_millis(200)).await;
        assert!(!r.ok);
        assert!(r.err.is_some());
    }

    #[tokio::test]
    #[ignore = "needs real network on wlo1"]
    async fn real_ping_gateway_and_internet() {
        let link = crate::link::read("wlo1");
        let gw = link.gateway.expect("gateway");
        for dst in [gw, Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)] {
            let r = ping("wlo1", dst, Duration::from_secs(1)).await;
            println!("ping {dst}: {r:?}");
            assert!(r.ok, "{dst}: {r:?}");
        }
        // TEST-NET-1 never answers.
        let r = ping(
            "wlo1",
            Ipv4Addr::new(192, 0, 2, 1),
            Duration::from_millis(300),
        )
        .await;
        println!("ping 192.0.2.1: {r:?}");
        assert!(!r.ok);
    }

    #[tokio::test]
    #[ignore = "needs real network on wlo1"]
    async fn real_ttl_walk() {
        for ttl in 1..=4 {
            let hop = probe_ttl(
                "wlo1",
                Ipv4Addr::new(1, 1, 1, 1),
                ttl,
                Duration::from_secs(1),
            )
            .await;
            println!("ttl {ttl}: {hop:?}");
        }
        let hop1 = probe_ttl("wlo1", Ipv4Addr::new(1, 1, 1, 1), 1, Duration::from_secs(1)).await;
        assert!(hop1.is_some());
    }
}
