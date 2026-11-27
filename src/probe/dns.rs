//! Minimal DNS A query over UDP, bound to one interface.
//!
//! The query is built by hand (random id, RD=1, one question, QTYPE A,
//! QCLASS IN). A reply counts when its id matches, QR is set and the question
//! echoes ours. RCODE NOERROR and NXDOMAIN are both `ok`: the server answered.

use super::{err_code, ms, random_bytes};
use crate::model::ProbeResult;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

const QTYPE_A: u16 = 1;
const QCLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;

/// Sends one A query for `name` to `server:53` through `iface`.
#[allow(dead_code)]
pub async fn query(iface: &str, server: Ipv4Addr, name: &str, timeout: Duration) -> ProbeResult {
    query_with_answers(iface, server, name, timeout).await.0
}

/// Sends one A query for `name` to `server:53` through `iface`, returning both the probe
/// status and any IPv4 A-record answers parsed from the reply.
pub async fn query_with_answers(
    iface: &str,
    server: Ipv4Addr,
    name: &str,
    timeout: Duration,
) -> (ProbeResult, Vec<Ipv4Addr>) {
    let deadline = Instant::now() + timeout;
    let rnd = random_bytes();
    let id = u16::from_be_bytes([rnd[0], rnd[1]]);
    let Some(q) = build_query(id, name) else {
        return (ProbeResult::fail("bad_name"), Vec::new());
    };
    let sock = match open(iface, server) {
        Ok(s) => s,
        Err(code) => return (ProbeResult::fail(code), Vec::new()),
    };
    let start = Instant::now();
    match timeout_at(deadline, sock.send(&q)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return (ProbeResult::fail(err_code(&e, "send_failed")), Vec::new()),
        Err(_) => return (ProbeResult::fail("timeout"), Vec::new()),
    }
    let mut buf = [0u8; 1500];
    loop {
        match timeout_at(deadline, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let pkt = buf.get(..n).unwrap_or_default();
                match check_reply(pkt, &q) {
                    Reply::Foreign => continue,
                    Reply::Ok => {
                        let answers = parse_a_answers(pkt, q.len());
                        return (ProbeResult::ok(ms(start.elapsed())), answers);
                    }
                    Reply::Rcode(code) => return (ProbeResult::fail(rcode_name(code)), Vec::new()),
                }
            }
            // ICMP port unreachable from the server shows up as ECONNREFUSED.
            Ok(Err(e)) => return (ProbeResult::fail(err_code(&e, "recv_failed")), Vec::new()),
            Err(_) => return (ProbeResult::fail("timeout"), Vec::new()),
        }
    }
}

/// Parses IPv4 A records from a validated DNS response whose question has length `q_len`.
pub(crate) fn parse_a_answers(r: &[u8], q_len: usize) -> Vec<Ipv4Addr> {
    if r.len() < HEADER_LEN || r.len() < q_len {
        return Vec::new();
    }
    let qd = u16::from_be_bytes([r[4], r[5]]);
    if qd != 1 {
        return Vec::new();
    }
    let an = u16::from_be_bytes([r[6], r[7]]);
    let mut off = q_len;
    let mut out = Vec::new();
    for _ in 0..an {
        let Some(next) = skip_name(r, off) else { break };
        off = next;
        let Some(hdr) = r.get(off..off + 10) else { break };
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let rclass = u16::from_be_bytes([hdr[2], hdr[3]]);
        let rdlen = usize::from(u16::from_be_bytes([hdr[8], hdr[9]]));
        off += 10;
        let Some(rdata) = r.get(off..off + rdlen) else { break };
        if rtype == QTYPE_A && rclass == QCLASS_IN && rdata.len() == 4 {
            out.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
        }
        off += rdlen;
    }
    out
}

/// Skips a DNS wire name (labels or compression pointers, loop-bounded).
fn skip_name(buf: &[u8], mut off: usize) -> Option<usize> {
    loop {
        let b = *buf.get(off)?;
        if b == 0 {
            return Some(off + 1);
        }
        if b & 0xc0 == 0xc0 {
            let b2 = *buf.get(off + 1)?;
            let after = off + 2;
            let mut cur = usize::from(u16::from_be_bytes([b & 0x3f, b2]));
            let mut jumps = 0u8;
            loop {
                if cur >= buf.len() || jumps >= 16 {
                    return None;
                }
                let lb = *buf.get(cur)?;
                if lb == 0 {
                    return Some(after);
                }
                if lb & 0xc0 == 0xc0 {
                    let nb2 = *buf.get(cur + 1)?;
                    cur = usize::from(u16::from_be_bytes([lb & 0x3f, nb2]));
                    jumps += 1;
                    continue;
                }
                if lb & 0xc0 != 0 {
                    return None;
                }
                cur = cur.checked_add(1 + usize::from(lb))?;
            }
        }
        if b & 0xc0 != 0 {
            return None;
        }
        off = off.checked_add(1 + usize::from(b))?;
    }
}

fn open(iface: &str, server: Ipv4Addr) -> Result<tokio::net::UdpSocket, &'static str> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| err_code(&e, "socket_failed"))?;
    s.set_nonblocking(true)
        .map_err(|e| err_code(&e, "socket_failed"))?;
    s.bind_device(Some(iface.as_bytes()))
        .map_err(|e| err_code(&e, "bind_failed"))?;
    s.connect(&SockAddr::from(SocketAddrV4::new(server, 53)))
        .map_err(|e| err_code(&e, "connect_failed"))?;
    let std_sock: std::net::UdpSocket = s.into();
    tokio::net::UdpSocket::from_std(std_sock).map_err(|e| err_code(&e, "socket_failed"))
}

/// Builds the query message, `None` if `name` is not a valid DNS name.
fn build_query(id: u16, name: &str) -> Option<Vec<u8>> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    let mut q = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, AN=NS=AR=0
    for label in name.split('.') {
        let len = u8::try_from(label.len()).ok()?;
        if len == 0 || len > 63 {
            return None;
        }
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&QTYPE_A.to_be_bytes());
    q.extend_from_slice(&QCLASS_IN.to_be_bytes());
    Some(q)
}

#[derive(Debug, PartialEq)]
enum Reply {
    /// Not a reply to our query (wrong id, not a response, wrong question).
    Foreign,
    /// Server answered with NOERROR or NXDOMAIN.
    Ok,
    /// Server answered with another RCODE.
    Rcode(u8),
}

fn check_reply(r: &[u8], query: &[u8]) -> Reply {
    if r.len() < HEADER_LEN || query.len() < HEADER_LEN || r[0..2] != query[0..2] {
        return Reply::Foreign;
    }
    let qr = r[2] & 0x80 != 0;
    if !qr {
        return Reply::Foreign;
    }
    // The question section must echo ours (case-insensitive name per RFC 4343).
    let qd = u16::from_be_bytes([r[4], r[5]]);
    let our_q = &query[HEADER_LEN..];
    if qd >= 1 {
        match r.get(HEADER_LEN..HEADER_LEN + our_q.len()) {
            Some(theirs) if theirs.eq_ignore_ascii_case(our_q) => {}
            _ => return Reply::Foreign,
        }
    }
    match r[3] & 0x0f {
        0 | 3 => Reply::Ok,
        code => Reply::Rcode(code),
    }
}

fn rcode_name(code: u8) -> &'static str {
    match code {
        1 => "dns_formerr",
        2 => "dns_servfail",
        4 => "dns_notimp",
        5 => "dns_refused",
        _ => "dns_rcode",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_bytes() {
        let q = build_query(0xabcd, "example.com.").unwrap();
        let want: &[u8] = &[
            0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
            b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert_eq!(q, want);
        assert!(build_query(1, "").is_none());
        assert!(build_query(1, "a..b").is_none());
        assert!(build_query(1, &"x".repeat(64)).is_none());
        assert!(build_query(1, &"a.".repeat(130)).is_none());
    }

    fn reply_for(q: &[u8], rcode: u8) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] |= 0x80;
        r[3] = 0x80 | rcode;
        r
    }

    #[test]
    fn reply_checks() {
        let q = build_query(0x1111, "Example.com").unwrap();
        assert_eq!(check_reply(&reply_for(&q, 0), &q), Reply::Ok);
        assert_eq!(check_reply(&reply_for(&q, 3), &q), Reply::Ok);
        assert_eq!(check_reply(&reply_for(&q, 2), &q), Reply::Rcode(2));
        let mut lower = reply_for(&q, 0);
        lower[HEADER_LEN + 1] = b'e';
        assert_eq!(check_reply(&lower, &q), Reply::Ok);
        let mut wrong_id = reply_for(&q, 0);
        wrong_id[1] ^= 1;
        assert_eq!(check_reply(&wrong_id, &q), Reply::Foreign);
        assert_eq!(check_reply(&q, &q), Reply::Foreign, "QR not set");
        assert_eq!(check_reply(&reply_for(&q, 0)[..5], &q), Reply::Foreign);
        assert_eq!(check_reply(&reply_for(&q, 0)[..14], &q), Reply::Foreign);
        assert_eq!(check_reply(&[], &q), Reply::Foreign);
    }

    #[test]
    fn a_answers_parse_safely() {
        let q = build_query(0x1111, "example.com").unwrap();
        let mut r = reply_for(&q, 0);
        r[6..8].copy_from_slice(&2u16.to_be_bytes());
        // Answer 1: pointer to offset 12, type A (1), class IN (1), ttl 60, len 4, 203.0.113.10
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
        // Answer 2: pointer to offset 12, type AAAA (28), class IN (1), ttl 60, len 16
        r.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        r.extend_from_slice(&[0u8; 16]);
        assert_eq!(parse_a_answers(&r, q.len()), vec![Ipv4Addr::new(203, 0, 113, 10)]);

        // Self-pointing pointer loop must terminate cleanly with empty vec.
        let mut cyc = reply_for(&q, 0);
        cyc[6..8].copy_from_slice(&1u16.to_be_bytes());
        let ptr_off = cyc.len() as u16;
        cyc.extend_from_slice(&((0xc000u16 | ptr_off).to_be_bytes()));
        cyc.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        assert!(parse_a_answers(&cyc, q.len()).is_empty());

        // Truncated RDATA must not panic.
        let mut trunc = reply_for(&q, 0);
        trunc[6..8].copy_from_slice(&1u16.to_be_bytes());
        trunc.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2]);
        assert!(parse_a_answers(&trunc, q.len()).is_empty());
    }

    #[tokio::test]
    #[ignore = "needs real network on wlo1"]
    async fn real_query() {
        let r = query(
            "wlo1",
            Ipv4Addr::new(1, 1, 1, 1),
            "example.com",
            Duration::from_secs(1),
        )
        .await;
        println!("dns 1.1.1.1 example.com {r:?}");
        assert!(r.ok);
        let r = query(
            "wlo1",
            Ipv4Addr::new(1, 1, 1, 1),
            "nonexistent.invalid",
            Duration::from_secs(1),
        )
        .await;
        println!("dns 1.1.1.1 nxdomain {r:?}");
        assert!(r.ok);
        for s in crate::link::resolv_conf_servers() {
            let r = query("wlo1", s, "example.com", Duration::from_secs(1)).await;
            println!("dns {s} {r:?}");
        }
    }
}
