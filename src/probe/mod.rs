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

/// Echo requests sent to a discovered hop before it is trusted.
const ECHO_CHECK_TRIES: u32 = 3;
/// Time for one echo request of the check (about 3 s in total).
const ECHO_CHECK_TIMEOUT: Duration = Duration::from_secs(1);

/// What a TTL-walk responder is, for ISP-hop discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopClass {
    /// Gateway, LAN member, walk target or bogus address: ignore.
    Skip,
    /// Private or CGNAT address that is not the gateway: a second NAT box
    /// of the user (double NAT), not the ISP. Look further.
    SecondNat,
    /// Public address: a candidate for the ISP first hop.
    Public,
}

/// True for RFC 1918 (10/8, 172.16/12, 192.168/16) and CGNAT 100.64.0.0/10.
fn is_private_or_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private() || (o[0] == 100 && (o[1] & 0xC0) == 64)
}

fn classify_hop(hop: Ipv4Addr, gateway: Ipv4Addr, lan: Option<(Ipv4Addr, u8)>) -> HopClass {
    if !is_isp_candidate(hop, gateway, lan) {
        HopClass::Skip
    } else if is_private_or_cgnat(hop) {
        HopClass::SecondNat
    } else {
        HopClass::Public
    }
}

/// Acceptance rule: one answered echo out of the tries is enough.
fn echo_accepted(answered: u32) -> bool {
    answered >= 1
}

/// Sends up to [`ECHO_CHECK_TRIES`] echo requests; stops at the first reply.
async fn answers_echo(iface: &str, hop: Ipv4Addr) -> bool {
    let mut answered = 0;
    for _ in 0..ECHO_CHECK_TRIES {
        if icmp::ping(iface, hop, ECHO_CHECK_TIMEOUT).await.ok {
            answered += 1;
            break;
        }
    }
    echo_accepted(answered)
}

/// First ISP hop after the gateway that is outside the LAN subnet of `iface`
/// and that answers ICMP echo.
///
/// Walks TTL 2..=4 towards 1.1.1.1 ("time exceeded" replies). The hop is
/// pinged every tick later, and the classifier reads "ISP hop silent" as a
/// line fault. So a hop is trusted only if it answers echo. Many ISP access
/// routers (BNG/BRAS) never do. Without this check every internet outage
/// would be blamed on the line.
///
/// A private or CGNAT hop that is not the gateway is the user's own second
/// NAT box (double NAT). It says nothing about the line, so the walk
/// continues (up to TTL 4) for a public hop. If the first public hop is
/// silent, there is no ISP hop (`None`): the walk does not go on to a later
/// router, which would not be the first hop.
/// Returns `None` if nothing usable is found within `timeout` per TTL.
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
        match classify_hop(hop, gateway, lan) {
            HopClass::Skip => {}
            HopClass::SecondNat => {
                tracing::info!(%iface, %hop, ttl, "ISP hop candidate is private (second NAT box); looking further");
            }
            HopClass::Public => {
                if answers_echo(iface, hop).await {
                    return Some(hop);
                }
                tracing::info!(%iface, %hop, ttl, "ISP hop candidate does not answer echo; not used, ISP checks stay off");
                return None;
            }
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
        assert!(is_isp_candidate(Ipv4Addr::new(10, 0, 0, 1), gw, lan));
        assert!(is_isp_candidate(Ipv4Addr::new(203, 0, 113, 1), gw, None));
        assert!(!is_isp_candidate(ISP_WALK_TARGET, gw, lan));
    }

    #[test]
    fn private_and_cgnat_ranges() {
        for a in [[10, 1, 2, 3], [172, 16, 0, 1], [172, 31, 255, 1], [192, 168, 1, 1], [100, 64, 0, 1], [100, 127, 255, 254]] {
            assert!(is_private_or_cgnat(Ipv4Addr::from(a)), "{a:?}");
        }
        for a in [[172, 32, 0, 1], [172, 15, 0, 1], [100, 63, 255, 255], [100, 128, 0, 1], [203, 0, 113, 1], [8, 8, 8, 8]] {
            assert!(!is_private_or_cgnat(Ipv4Addr::from(a)), "{a:?}");
        }
    }

    #[test]
    fn hop_classes() {
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        let lan = Some((Ipv4Addr::new(192, 168, 0, 42), 24));
        assert_eq!(classify_hop(gw, gw, lan), HopClass::Skip);
        assert_eq!(classify_hop(Ipv4Addr::new(192, 168, 0, 7), gw, lan), HopClass::Skip);
        assert_eq!(classify_hop(ISP_WALK_TARGET, gw, lan), HopClass::Skip);
        // Double NAT: private hop outside the LAN that is not the gateway.
        assert_eq!(classify_hop(Ipv4Addr::new(192, 168, 1, 1), gw, lan), HopClass::SecondNat);
        assert_eq!(classify_hop(Ipv4Addr::new(10, 0, 0, 1), gw, lan), HopClass::SecondNat);
        assert_eq!(classify_hop(Ipv4Addr::new(100, 64, 0, 1), gw, lan), HopClass::SecondNat);
        assert_eq!(classify_hop(Ipv4Addr::new(203, 0, 113, 1), gw, lan), HopClass::Public);
    }

    #[test]
    fn echo_acceptance_rule() {
        assert!(!echo_accepted(0));
        assert!(echo_accepted(1));
        assert!(echo_accepted(3));
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
