//! Readiness advisor (docs/ADVISOR.md): turns `check` items into "what spoils which conclusion".
//!
//! Rules: an item exists only when it changes a conclusion (`spoils`); it carries its evidence and
//! threshold; there is one top action; accepted risks are silent.

use super::{Item, Level};
use crate::config::Config;

/// One rule: stable code, the question it spoils, the threshold, blocking flag.
/// Table order is priority order (most damaging first).
pub struct Rule {
    pub code: &'static str,
    pub spoils: &'static str,
    pub threshold: &'static str,
    pub blocking: bool,
}

pub const RULES: &[Rule] = &[
    Rule { code: "icmp_permission", spoils: "every probe (no ping is possible)", threshold: "gid inside net.ipv4.ping_group_range", blocking: true },
    Rule { code: "data_dir", spoils: "recording (nothing can be saved)", threshold: "data_dir writable", blocking: true },
    Rule { code: "wifi_blocked", spoils: "the Wi-Fi path (radio is blocked)", threshold: "rfkill soft and hard block off", blocking: true },
    Rule { code: "path_isolation", spoils: "Wi-Fi vs Ethernet separation (replies return on the wrong interface or path is dead)", threshold: "reply arrives on the sending interface, rp_filter < 1, arp_ignore=1 and arp_announce=2 on a shared subnet", blocking: true },
    Rule { code: "no_wired_path", spoils: "Wi-Fi vs router/ISP separation (no wired reference)", threshold: "Ethernet present, carrier up, gateway answers", blocking: false },
    Rule { code: "vpn_active", spoils: "ISP and internet verdicts (probes may leave through the tunnel)", threshold: "no tunnel interface up", blocking: false },
    Rule { code: "clock_unsynced", spoils: "cross-device compare and router-log matching", threshold: "NTP synchronized", blocking: false },
    Rule { code: "wifi_power_save", spoils: "latency numbers (RTT inflated, jitter added)", threshold: "power_save off", blocking: false },
    Rule { code: "bluetooth_24ghz", spoils: "Wi-Fi latency numbers (shared 2.4 GHz antenna)", threshold: "Bluetooth off, or Wi-Fi not on 2.4 GHz", blocking: false },
    Rule { code: "timer_jitter", spoils: "latency numbers (host wake-up delay)", threshold: "wake-up delay p99 < 5 ms", blocking: false },
    Rule { code: "host_pressure", spoils: "latency numbers and loss (probe ticks run late)", threshold: "PSI some avg10 < 5%", blocking: false },
    Rule { code: "conntrack_full", spoils: "loss figures (the host drops new flows)", threshold: "conntrack use < 70%", blocking: false },
    Rule { code: "two_net_managers", spoils: "link-drop causes (managers re-apply routes or DHCP)", threshold: "one network manager per interface", blocking: false },
    Rule { code: "random_mac", spoils: "router device counts and DHCP/ARP stability", threshold: "permanent MAC address", blocking: false },
    Rule { code: "clock_loose", spoils: "tight cross-device alignment", threshold: "clock max error <= 100 ms", blocking: false },
    Rule { code: "disk_low", spoils: "run length (recording may stop early)", threshold: "free space >= [storage] min_free_bytes", blocking: false },
];

/// Look up a rule by code.
pub fn rule(code: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.code == code)
}

/// A user may accept every non-blocking risk.
pub fn is_acceptable(code: &str) -> bool {
    rule(code).is_some_and(|r| !r.blocking)
}

pub fn acceptable_codes() -> Vec<&'static str> {
    RULES.iter().filter(|r| !r.blocking).map(|r| r.code).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyLevel {
    Go,
    GoWithCaveats,
    NoGo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyItem {
    pub code: &'static str,
    /// The question this condition spoils.
    pub spoils: &'static str,
    /// What was measured, with the threshold.
    pub evidence: String,
    pub fix: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub level: ReadyLevel,
    /// The one action to do first (the first blocker, else the most damaging caveat).
    pub top: Option<ReadyItem>,
    /// All other items, in priority order. `top` is not repeated here.
    pub items: Vec<ReadyItem>,
}

pub fn assess(items: &[Item], cfg: &Config) -> Readiness {
    let mut found: Vec<(usize, ReadyItem)> = Vec::new();
    for it in items {
        if it.level == Level::Ok || it.code.is_empty() {
            continue;
        }
        let Some((pos, r)) = RULES.iter().enumerate().find(|(_, r)| r.code == it.code) else { continue };
        // Blocking rules only block when the check really failed.
        let blocking = r.blocking && it.level == Level::Fail;
        if !blocking && cfg.advisor.accept.iter().any(|a| a == r.code) {
            continue;
        }
        if found.iter().any(|(_, f)| f.code == r.code && f.evidence == format!("{} (threshold: {})", it.detail, r.threshold)) {
            continue;
        }
        found.push((
            pos,
            ReadyItem {
                code: r.code,
                spoils: r.spoils,
                evidence: format!("{} (threshold: {})", it.detail, r.threshold),
                fix: it.fix.clone().unwrap_or_else(|| "see docs/ADVISOR.md".into()),
                blocking,
            },
        ));
    }
    found.sort_by_key(|(pos, i)| (!i.blocking, *pos));
    let mut list: Vec<ReadyItem> = found.into_iter().map(|(_, i)| i).collect();
    let level = if list.iter().any(|i| i.blocking) {
        ReadyLevel::NoGo
    } else if list.is_empty() {
        ReadyLevel::Go
    } else {
        ReadyLevel::GoWithCaveats
    };
    let top = if list.is_empty() { None } else { Some(list.remove(0)) };
    Readiness { level, top, items: list }
}

/// Prints the readiness block after the check lines.
pub fn print(r: &Readiness) {
    println!();
    let word = match r.level {
        ReadyLevel::Go => "GO: nothing found that spoils a conclusion",
        ReadyLevel::GoWithCaveats => "GO WITH CAVEATS: the run works, some conclusions will be weaker",
        ReadyLevel::NoGo => "NO-GO: fix the blocking item before the run",
    };
    println!("readiness: {word}");
    let Some(top) = &r.top else { return };
    println!("  top action: {}", top.fix);
    println!("    [{}] spoils: {}", top.code, top.spoils);
    println!("    evidence: {}", top.evidence);
    if !r.items.is_empty() {
        println!("  also:");
        for i in &r.items {
            println!("    - [{}] spoils: {}", i.code, i.spoils);
            println!("      evidence: {}", i.evidence);
            println!("      fix: {}", i.fix);
        }
    }
    println!("  accept a risk with [advisor] accept = [\"<code>\"] in the config.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::item;

    fn cfg(accept: &[&str]) -> Config {
        let mut c = Config::default();
        c.advisor.accept = accept.iter().map(|s| s.to_string()).collect();
        c
    }

    #[test]
    fn all_ok_is_go() {
        let items = vec![item(Level::Ok, "clock", "NTP synchronized", None).code("clock_unsynced"), item(Level::Ok, "x", "y", None)];
        let r = assess(&items, &cfg(&[]));
        assert_eq!(r.level, ReadyLevel::Go);
        assert!(r.top.is_none() && r.items.is_empty());
    }

    #[test]
    fn caveats_order_and_top() {
        let items = vec![
            item(Level::Warn, "wifi power_save wlo1", "power_save is ON", Some("iw off")).code("wifi_power_save"),
            item(Level::Warn, "wired path", "no Ethernet interface is monitored", Some("plug cable")).code("no_wired_path"),
            item(Level::Warn, "other", "no code", None),
        ];
        let r = assess(&items, &cfg(&[]));
        assert_eq!(r.level, ReadyLevel::GoWithCaveats);
        let top = r.top.unwrap();
        assert_eq!(top.code, "no_wired_path");
        assert!(top.spoils.contains("Wi-Fi vs router/ISP"));
        assert!(top.evidence.contains("threshold:"));
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].code, "wifi_power_save");
    }

    #[test]
    fn blocking_wins_and_cannot_be_accepted() {
        let items = vec![
            item(Level::Warn, "wired path", "none", None).code("no_wired_path"),
            item(Level::Fail, "icmp permission", "gid 1000", Some("sysctl")).code("icmp_permission"),
        ];
        let r = assess(&items, &cfg(&["icmp_permission"]));
        assert_eq!(r.level, ReadyLevel::NoGo);
        assert_eq!(r.top.as_ref().unwrap().code, "icmp_permission");
        assert!(r.top.unwrap().blocking);
    }

    #[test]
    fn accepted_risk_is_silent() {
        let items = vec![item(Level::Warn, "wired path", "none", None).code("no_wired_path")];
        let r = assess(&items, &cfg(&["no_wired_path"]));
        assert_eq!(r.level, ReadyLevel::Go);
        assert!(r.top.is_none());
    }

    #[test]
    fn warn_on_blocking_rule_is_not_blocking() {
        let items = vec![item(Level::Warn, "icmp permission", "cannot read ping_group_range", None).code("icmp_permission")];
        assert_eq!(assess(&items, &cfg(&[])).level, ReadyLevel::GoWithCaveats);
    }

    #[test]
    fn every_rule_code_is_unique_and_known() {
        for (i, r) in RULES.iter().enumerate() {
            assert!(!RULES[..i].iter().any(|o| o.code == r.code), "{}", r.code);
        }
        assert!(is_acceptable("vpn_active") && !is_acceptable("data_dir") && !is_acceptable("nope"));
    }
}
