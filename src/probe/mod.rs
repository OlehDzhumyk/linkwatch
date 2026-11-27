//! Active probes, each bound to one interface with `SO_BINDTODEVICE`.
//!
//! * [`icmp`]: unprivileged ICMP echo (`SOCK_DGRAM`/`IPPROTO_ICMP`) and a
//!   TTL-limited variant for hop discovery.
//! * [`tcp`]: TCP connect; a refused connection still proves reachability.
//! * [`dns`]: a hand-built DNS A query over UDP.
//!
//! Every probe has an explicit timeout and never panics. Failures are
//! reported as [`ProbeResult::fail`] with a short machine-readable code.
//!
//! [`ProbeResult::fail`]: crate::model::ProbeResult::fail

pub mod dns;
pub mod icmp;
pub mod tcp;

use std::io;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Target of the TTL walk used for ISP-hop discovery.
const ISP_WALK_TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// First hop after the gateway that is not in the LAN subnet of `iface`.
///
/// Walks TTL 2..=4 towards 1.1.1.1 and returns the first responder that is
/// neither the gateway, nor inside the LAN subnet, nor the walk target itself.
/// Private (RFC 1918) addresses outside the LAN are accepted, because some
/// cable ISPs use RFC 1918 addresses for their first hop.
/// Returns `None` if no hop answers within `timeout` per TTL.
pub async fn discover_isp_hop(
    iface: &str,
    gateway: Ipv4Addr,
    timeout: Duration,
) -> Option<Ipv4Addr> {
    let link = crate::link::read(iface);
    let lan = link.ipv4.zip(link.prefix_len);
    for ttl in 2..=4u8 {
        let Some(hop) = icmp::probe_ttl(iface, ISP_WALK_TARGET, ttl, timeout).await else {
            continue;
        };
        if is_isp_candidate(hop, gateway, lan) {
            return Some(hop);
        }
    }
    None
}

fn is_isp_candidate(hop: Ipv4Addr, gateway: Ipv4Addr, lan: Option<(Ipv4Addr, u8)>) -> bool {
    if hop == gateway || hop == ISP_WALK_TARGET || hop.is_unspecified() || hop.is_loopback() {
        return false;
    }
    match lan {
        Some((addr, prefix)) => !crate::link::in_subnet(hop, addr, prefix),
        None => true,
    }
}

/// Maps a socket error to a probe error code, `fallback` when not specific.
pub(crate) fn err_code(e: &io::Error, fallback: &'static str) -> &'static str {
    if e.kind() == io::ErrorKind::TimedOut {
        return "timeout";
    }
    match e.raw_os_error() {
        Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EHOSTDOWN) => "unreachable",
        Some(libc::ENETDOWN) => "net_down",
        Some(libc::ENODEV) => "no_device",
        Some(libc::EPERM | libc::EACCES) => "permission",
        Some(libc::ECONNREFUSED) => "refused",
        Some(libc::EADDRNOTAVAIL) => "no_addr",
        _ => fallback,
    }
}

/// 16 random bytes (from the OS RNG via uuid v4) for ids and payload tokens.
pub(crate) fn random_bytes() -> [u8; 16] {
    *uuid::Uuid::new_v4().as_bytes()
}

/// Milliseconds as f64 for RTT reporting.
pub(crate) fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isp_candidate_rules() {
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        let lan = Some((Ipv4Addr::new(192, 168, 0, 42), 24));
        assert!(!is_isp_candidate(gw, gw, lan));
        assert!(!is_isp_candidate(Ipv4Addr::new(192, 168, 0, 2), gw, lan));
        // An RFC 1918 first hop outside the LAN (used by some cable ISPs): accept.
        assert!(is_isp_candidate(Ipv4Addr::new(10, 0, 0, 1), gw, lan));
        assert!(is_isp_candidate(Ipv4Addr::new(203, 0, 113, 1), gw, None));
        assert!(!is_isp_candidate(ISP_WALK_TARGET, gw, lan));
    }

    #[test]
    fn error_codes() {
        let e = io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        assert_eq!(err_code(&e, "x"), "unreachable");
        let e = io::Error::from_raw_os_error(libc::ENODEV);
        assert_eq!(err_code(&e, "x"), "no_device");
        let e = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(err_code(&e, "x"), "permission");
        let e = io::Error::from_raw_os_error(libc::EINVAL);
        assert_eq!(err_code(&e, "x"), "x");
    }

    #[tokio::test]
    #[ignore = "needs real network on wlo1"]
    async fn real_isp_hop() {
        let link = crate::link::read("wlo1");
        let gw = link.gateway.expect("gateway on wlo1");
        let hop = discover_isp_hop("wlo1", gw, Duration::from_secs(1)).await;
        println!("gateway {gw} isp hop {hop:?}");
        assert!(hop.is_some());
    }
}
