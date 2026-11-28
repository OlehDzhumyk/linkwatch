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
    /// RFC 1918 address that is not the gateway: either the ISP's own first hop (cable ISPs
    /// often use 10.x for the CMTS side) or a second NAT box of the user (double NAT).
    /// [`is_local_box`] decides by RTT.
    Private,
    /// Public or CGNAT (100.64.0.0/10, always ISP equipment) address: a candidate.
    Public,
}

/// True for RFC 1918 (10/8, 172.16/12, 192.168/16).
fn is_rfc1918(ip: Ipv4Addr) -> bool {
    ip.is_private()
}

fn classify_hop(hop: Ipv4Addr, gateway: Ipv4Addr, lan: Option<(Ipv4Addr, u8)>) -> HopClass {
    if !is_isp_candidate(hop, gateway, lan) {
        HopClass::Skip
    } else if is_rfc1918(hop) {
        HopClass::Private
    } else {
        HopClass::Public
    }
}

/// A private hop that answers within this much of the gateway's RTT sits in the same home
/// (a second router or modem in router mode). An ISP first hop behind a DOCSIS/DSL/fibre line
/// is several ms further: the line itself adds that delay. Engineering estimate.
const LOCAL_BOX_EXTRA_MS: f64 = 1.0;

fn is_local_box(hop_rtt_ms: f64, gw_rtt_ms: f64) -> bool {
    hop_rtt_ms - gw_rtt_ms < LOCAL_BOX_EXTRA_MS
}

/// Best (lowest) RTT of a few echoes, `None` when none answers.
async fn best_rtt(iface: &str, dst: Ipv4Addr) -> Option<f64> {
    let mut best: Option<f64> = None;
    for _ in 0..ECHO_CHECK_TRIES {
        let r = icmp::ping(iface, dst, ECHO_CHECK_TIMEOUT).await;
        if let Some(v) = r.rtt_ms.filter(|_| r.ok) {
            best = Some(best.map_or(v, |b: f64| b.min(v)));
        }
    }
    best
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
/// A private (RFC 1918) hop is either the ISP's first hop (cable ISPs often
/// use 10.x) or the user's own second NAT box. A hop that answers within
/// about 1 ms of the gateway is at home: the walk continues (up to TTL 4).
/// CGNAT (100.64.0.0/10) is always ISP equipment. If the first public hop is
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
            HopClass::Private => {
                let Some(hop_rtt) = best_rtt(iface, hop).await else {
                    tracing::info!(%iface, %hop, ttl, "private ISP hop candidate does not answer echo; not used, ISP checks stay off");
                    return None;
                };
                match best_rtt(iface, gateway).await {
                    Some(gw_rtt) if is_local_box(hop_rtt, gw_rtt) => {
                        tracing::info!(%iface, %hop, ttl, hop_rtt, gw_rtt, "private hop answers as fast as the gateway: second NAT box at home; looking further");
                    }
                    _ => return Some(hop),
                }
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
    fn rfc1918_ranges() {
        for a in [[10, 1, 2, 3], [172, 16, 0, 1], [172, 31, 255, 1], [192, 168, 1, 1]] {
            assert!(is_rfc1918(Ipv4Addr::from(a)), "{a:?}");
        }
        // CGNAT is ISP space, not a home box.
        for a in [[172, 32, 0, 1], [172, 15, 0, 1], [100, 64, 0, 1], [100, 127, 255, 254], [203, 0, 113, 1], [8, 8, 8, 8]] {
            assert!(!is_rfc1918(Ipv4Addr::from(a)), "{a:?}");
        }
    }

    #[test]
    fn hop_classes() {
        let gw = Ipv4Addr::new(192, 168, 0, 1);
        let lan = Some((Ipv4Addr::new(192, 168, 0, 42), 24));
        assert_eq!(classify_hop(gw, gw, lan), HopClass::Skip);
        assert_eq!(classify_hop(Ipv4Addr::new(192, 168, 0, 7), gw, lan), HopClass::Skip);
        assert_eq!(classify_hop(ISP_WALK_TARGET, gw, lan), HopClass::Skip);
        // Private hop outside the LAN: ISP (cable 10.x) or a second home router; decided by RTT.
        assert_eq!(classify_hop(Ipv4Addr::new(192, 168, 1, 1), gw, lan), HopClass::Private);
        assert_eq!(classify_hop(Ipv4Addr::new(10, 53, 39, 41), gw, lan), HopClass::Private);
        assert_eq!(classify_hop(Ipv4Addr::new(100, 64, 0, 1), gw, lan), HopClass::Public);
        assert_eq!(classify_hop(Ipv4Addr::new(203, 0, 113, 1), gw, lan), HopClass::Public);
    }

    #[test]
    fn local_box_by_rtt() {
        // Second router at home: 0.4 ms beyond the gateway.
        assert!(is_local_box(3.4, 3.0));
        // Cable ISP first hop: ~8 ms beyond the gateway.
        assert!(!is_local_box(11.0, 3.0));
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
