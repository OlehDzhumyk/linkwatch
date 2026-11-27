//! Wi-Fi statistics over nl80211 (generic netlink), hand-written.
//!
//! [`Nl80211`] owns one blocking netlink socket with a receive and send
//! timeout ([`NL_TIMEOUT`]), so no call can hang. The methods block for up to
//! that time: call them from `tokio::task::spawn_blocking` (the struct is
//! `Send`). Reading station, survey and cached scan results works
//! unprivileged; [`Nl80211::trigger_scan`] needs CAP_NET_ADMIN.

pub mod netlink;
pub mod nl80211;

use crate::model::{ChannelLoad, ScanBss, SurveyEntry, WifiStation};
use anyhow::{Context, Result, bail};
use netlink::{
    Attr, GENL_HDRLEN, GenlSocket, MsgBuilder, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, errno, find,
    parse_attrs,
};
use nl80211::*;
use std::time::Duration;

/// Receive/send timeout of the netlink socket.
pub const NL_TIMEOUT: Duration = Duration::from_secs(2);

/// An open nl80211 session.
#[derive(Debug)]
pub struct Nl80211 {
    sock: GenlSocket,
    family: u16,
}

/// What GET_INTERFACE tells about the current channel.
#[derive(Debug, Default, PartialEq)]
struct IfaceInfo {
    ssid: Option<String>,
    freq_mhz: Option<u32>,
    width_mhz: Option<u32>,
}

impl Nl80211 {
    /// Opens a netlink socket and resolves the "nl80211" family.
    pub fn open() -> Result<Self> {
        let mut sock = GenlSocket::open(NL_TIMEOUT)?;
        let family = sock
            .family_id("nl80211")
            .context("nl80211 is not available (no Wi-Fi driver loaded?)")?;
        Ok(Self { sock, family })
    }

    fn request(&mut self, cmd: u8, iface: &str, dump: bool) -> Result<Vec<Vec<u8>>> {
        let ifindex = ifindex(iface)?;
        let seq = self.sock.next_seq();
        let flags = NLM_F_REQUEST | if dump { NLM_F_DUMP } else { NLM_F_ACK };
        let req = MsgBuilder::new(self.family, flags, seq, cmd, 0)
            .attr_u32(ATTR_IFINDEX, ifindex)
            .finish();
        self.sock.request(&req, seq)
    }

    /// Station statistics of the AP we are associated with.
    /// `connected = false` (and no other fields) when not associated.
    pub fn station(&mut self, iface: &str) -> Result<WifiStation> {
        let mut st = WifiStation {
            iface: iface.to_string(),
            ..Default::default()
        };
        let stations = self
            .request(CMD_GET_STATION, iface, true)
            .context("GET_STATION")?;
        let Some(p) = stations.first() else {
            return Ok(st);
        };
        parse_station(genl_payload(p), &mut st)?;
        if !st.connected {
            return Ok(st);
        }
        let info = self
            .request(CMD_GET_INTERFACE, iface, false)
            .context("GET_INTERFACE")?
            .first()
            .map(|p| parse_interface(genl_payload(p)))
            .transpose()?
            .unwrap_or_default();
        st.freq_mhz = info.freq_mhz;
        st.channel = info.freq_mhz.and_then(freq_to_channel);
        st.width_mhz = info.width_mhz;
        st.ssid = info.ssid;
        if st.ssid.is_none() {
            // Older kernels do not report the SSID in GET_INTERFACE: take it
            // from the associated BSS in the scan cache.
            if let Ok(bss) = self.scan_results(iface) {
                st.ssid = bss.into_iter().find(|b| b.associated).and_then(|b| b.ssid);
            }
        }
        st.power_save = self.power_save(iface).ok().flatten();
        Ok(st)
    }

    /// Reads whether client Wi-Fi power-save is enabled (`CMD_GET_POWER_SAVE`).
    pub fn power_save(&mut self, iface: &str) -> Result<Option<bool>> {
        let msgs = self
            .request(CMD_GET_POWER_SAVE, iface, false)
            .context("GET_POWER_SAVE")?;
        let Some(p) = msgs.first() else {
            return Ok(None);
        };
        parse_power_save(genl_payload(p))
    }

    /// Channel survey of all frequencies the driver reports.
    ///
    /// Some drivers (seen with mt7921) never set the in-use flag. Then the
    /// entry matching the current operating frequency from GET_INTERFACE is
    /// marked `in_use`, so [`channel_load`] still has a channel to follow.
    pub fn survey(&mut self, iface: &str) -> Result<Vec<SurveyEntry>> {
        let msgs = self
            .request(CMD_GET_SURVEY, iface, true)
            .context("GET_SURVEY")?;
        let mut out = Vec::with_capacity(msgs.len());
        for p in &msgs {
            if let Some(e) = parse_survey(genl_payload(p))? {
                out.push(e);
            }
        }
        if !out.iter().any(|e| e.in_use) {
            let freq = self
                .request(CMD_GET_INTERFACE, iface, false)
                .ok()
                .and_then(|r| {
                    r.first()
                        .and_then(|p| parse_interface(genl_payload(p)).ok())
                })
                .and_then(|i| i.freq_mhz);
            mark_in_use(&mut out, freq);
        }
        Ok(out)
    }

    /// Starts an active scan. Results appear later in [`Self::scan_results`].
    /// A scan that is already running (EBUSY) counts as success.
    pub fn trigger_scan(&mut self, iface: &str) -> Result<()> {
        match self.request(CMD_TRIGGER_SCAN, iface, false) {
            Ok(_) => Ok(()),
            Err(e) => match errno(&e) {
                Some(libc::EPERM | libc::EACCES) => bail!(
                    "triggering a Wi-Fi scan on {iface} needs CAP_NET_ADMIN \
                     (run as root or grant cap_net_admin); only cached results are available"
                ),
                Some(libc::EBUSY) => Ok(()),
                _ => Err(e.context(format!("TRIGGER_SCAN on {iface}"))),
            },
        }
    }

    /// BSS list from the kernel scan cache.
    pub fn scan_results(&mut self, iface: &str) -> Result<Vec<ScanBss>> {
        let msgs = self
            .request(CMD_GET_SCAN, iface, true)
            .context("GET_SCAN")?;
        let mut out = Vec::with_capacity(msgs.len());
        for p in &msgs {
            if let Some(b) = parse_bss(genl_payload(p))? {
                out.push(b);
            }
        }
        Ok(out)
    }
}

/// Kernel MLME multicast events received on the nl80211 `mlme` group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlmeEvent {
    Disconnect {
        ifindex: u32,
        bssid: Option<String>,
        reason_code: Option<u16>,
        by_ap: Option<bool>,
        timed_out: bool,
    },
    ChannelSwitch {
        ifindex: u32,
        freq_mhz: u32,
    },
}

/// Non-blocking-friendly (timeout-bounded) nl80211 `mlme` multicast listener.
#[derive(Debug)]
pub struct Nl80211Events {
    sock: GenlSocket,
    family: u16,
}

impl Nl80211Events {
    pub fn open(timeout: Duration) -> Result<Self> {
        let mut ctrl = GenlSocket::open(NL_TIMEOUT)?;
        let (family, groups) = ctrl
            .family_info("nl80211")
            .context("nl80211 is not available")?;
        let group_id = groups
            .into_iter()
            .find(|(n, _)| n == "mlme")
            .map(|(_, id)| id)
            .context("nl80211 multicast group 'mlme' not found")?;
        let sock = GenlSocket::open_multicast(group_id, timeout)?;
        Ok(Self { sock, family })
    }

    /// Waits up to the socket timeout for multicast events and returns all parsed events.
    pub fn next_events(&mut self) -> Result<Vec<MlmeEvent>> {
        let Some(buf) = self.sock.recv_datagram()? else {
            return Ok(Vec::new());
        };
        let msgs = netlink::parse_messages(&buf)?;
        Ok(msgs
            .into_iter()
            .filter_map(|m| parse_mlme_msg(self.family, m))
            .collect())
    }
}

pub(crate) fn parse_power_save(attrs_buf: &[u8]) -> Result<Option<bool>> {
    let attrs = parse_attrs(attrs_buf)?;
    Ok(match find(&attrs, ATTR_PS_STATE).and_then(|a| a.u32()) {
        Some(PS_ENABLED) => Some(true),
        Some(PS_DISABLED) => Some(false),
        _ => None,
    })
}

pub(crate) fn parse_mlme_msg(family: u16, msg: netlink::Msg<'_>) -> Option<MlmeEvent> {
    if msg.ty != family {
        return None;
    }
    let cmd = *msg.payload.first()?;
    let attrs = parse_attrs(genl_payload(msg.payload)).ok()?;
    let ifindex = find(&attrs, ATTR_IFINDEX)?.u32()?;
    match cmd {
        CMD_DISCONNECT | CMD_DEAUTHENTICATE | CMD_DISASSOCIATE | CMD_CONN_FAILED => {
            let mut bssid = find(&attrs, ATTR_MAC).and_then(|a| mac_string(a.data));
            let mut reason_code = find(&attrs, ATTR_REASON_CODE).and_then(|a| a.u16());
            let mut by_ap = find(&attrs, ATTR_DISCONNECTED_BY_AP).map(|_| true);
            let timed_out = find(&attrs, ATTR_TIMED_OUT).is_some();
            if let Some(frame) = find(&attrs, ATTR_FRAME).map(|a| a.data)
                && frame.len() >= 26
            {
                if bssid.is_none() {
                    bssid = mac_string(&frame[16..22]);
                }
                if reason_code.is_none() && (frame[0] & 0x0c) == 0 && matches!(frame[0] & 0xf0, 0xa0 | 0xc0) {
                    reason_code = Some(u16::from_le_bytes([frame[24], frame[25]]));
                }
                if by_ap.is_none() {
                    by_ap = Some(frame[10..16] == frame[16..22]);
                }
            }
            Some(MlmeEvent::Disconnect {
                ifindex,
                bssid,
                reason_code,
                by_ap,
                timed_out,
            })
        }
        CMD_CH_SWITCH_NOTIFY => {
            let freq_mhz = find(&attrs, ATTR_WIPHY_FREQ)?.u32()?;
            Some(MlmeEvent::ChannelSwitch { ifindex, freq_mhz })
        }
        _ => None,
    }
}

fn ifindex(iface: &str) -> Result<u32> {
    match nix::net::if_::if_nametoindex(iface) {
        Ok(i) if i > 0 => Ok(i),
        _ => bail!("interface {iface} not found"),
    }
}

/// Attribute area of a generic-netlink message payload.
fn genl_payload(p: &[u8]) -> &[u8] {
    p.get(GENL_HDRLEN..).unwrap_or_default()
}

fn mac_string(b: &[u8]) -> Option<String> {
    let b: &[u8; 6] = b.get(..6)?.try_into().ok()?;
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    ))
}

/// Bitrate in Mbit/s from a nested `nl80211_rate_info`.
fn bitrate_mbps(a: &Attr<'_>) -> Result<Option<f64>> {
    let r = a.nested()?;
    let v = find(&r, RATE_INFO_BITRATE32)
        .and_then(|x| x.u32())
        .or_else(|| {
            find(&r, RATE_INFO_BITRATE)
                .and_then(|x| x.u16())
                .map(u32::from)
        });
    Ok(v.filter(|&v| v > 0).map(|v| f64::from(v) / 10.0))
}

fn parse_station(attrs_buf: &[u8], st: &mut WifiStation) -> Result<()> {
    let attrs = parse_attrs(attrs_buf)?;
    let Some(info) = find(&attrs, ATTR_STA_INFO) else {
        return Ok(());
    };
    st.connected = true;
    st.bssid = find(&attrs, ATTR_MAC).and_then(|a| mac_string(a.data));
    let info = info.nested()?;
    let u32_of = |k| find(&info, k).and_then(|a| a.u32());
    st.signal_dbm = find(&info, STA_INFO_SIGNAL)
        .and_then(|a| a.i8())
        .map(i32::from);
    st.signal_avg_dbm = find(&info, STA_INFO_SIGNAL_AVG)
        .and_then(|a| a.i8())
        .map(i32::from);
    st.tx_bitrate_mbps = find(&info, STA_INFO_TX_BITRATE)
        .map(|a| bitrate_mbps(&a))
        .transpose()?
        .flatten();
    st.rx_bitrate_mbps = find(&info, STA_INFO_RX_BITRATE)
        .map(|a| bitrate_mbps(&a))
        .transpose()?
        .flatten();
    st.tx_retries = u32_of(STA_INFO_TX_RETRIES);
    st.tx_failed = u32_of(STA_INFO_TX_FAILED);
    st.beacon_loss = u32_of(STA_INFO_BEACON_LOSS);
    st.connected_s = u32_of(STA_INFO_CONNECTED_TIME);
    Ok(())
}

fn ssid_string(raw: &[u8]) -> Option<String> {
    // Hidden networks report an empty or all-zero SSID.
    if raw.is_empty() || raw.iter().all(|&b| b == 0) {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

fn parse_interface(attrs_buf: &[u8]) -> Result<IfaceInfo> {
    let attrs = parse_attrs(attrs_buf)?;
    Ok(IfaceInfo {
        ssid: find(&attrs, ATTR_SSID).and_then(|a| ssid_string(a.data)),
        freq_mhz: find(&attrs, ATTR_WIPHY_FREQ).and_then(|a| a.u32()),
        width_mhz: find(&attrs, ATTR_CHANNEL_WIDTH)
            .and_then(|a| a.u32())
            .and_then(chan_width_mhz),
    })
}

fn parse_survey(attrs_buf: &[u8]) -> Result<Option<SurveyEntry>> {
    let attrs = parse_attrs(attrs_buf)?;
    let Some(info) = find(&attrs, ATTR_SURVEY_INFO) else {
        return Ok(None);
    };
    let s = info.nested()?;
    let Some(freq) = find(&s, SURVEY_INFO_FREQUENCY).and_then(|a| a.u32()) else {
        return Ok(None);
    };
    let u64_of = |k| find(&s, k).and_then(|a| a.u64());
    Ok(Some(SurveyEntry {
        freq_mhz: freq,
        in_use: find(&s, SURVEY_INFO_IN_USE).is_some(),
        noise_dbm: find(&s, SURVEY_INFO_NOISE)
            .and_then(|a| a.i8())
            .map(i32::from),
        active_ms: u64_of(SURVEY_INFO_TIME),
        busy_ms: u64_of(SURVEY_INFO_TIME_BUSY),
        rx_ms: u64_of(SURVEY_INFO_TIME_RX),
        tx_ms: u64_of(SURVEY_INFO_TIME_TX),
    }))
}

/// Marks the entry of `freq` as in use when the driver flagged none.
fn mark_in_use(entries: &mut [SurveyEntry], freq: Option<u32>) {
    if entries.iter().any(|e| e.in_use) {
        return;
    }
    if let Some(e) = freq.and_then(|f| entries.iter_mut().find(|e| e.freq_mhz == f)) {
        e.in_use = true;
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedIes {
    ssid: Option<String>,
    width_mhz: Option<u32>,
    has_rsn: bool,
    has_wpa1: bool,
    has_sae: bool,
    has_psk: bool,
    has_tkip: bool,
    wps: bool,
    pmf: Option<&'static str>,
}

fn parse_rsn_ie(data: &[u8], out: &mut ParsedIes) {
    // Version (2 B) + Group Data Cipher Suite (4 B) = at least 6 bytes for a valid RSN IE.
    if data.len() < 6 || u16::from_le_bytes([data[0], data[1]]) != 1 {
        return;
    }
    out.has_rsn = true;
    let mut pos = 6usize;
    let Some(pw_bytes) = data.get(pos..pos + 2) else {
        return;
    };
    let pw_count = usize::from(u16::from_le_bytes([pw_bytes[0], pw_bytes[1]]));
    pos += 2;
    let Some(pw_end) = pos.checked_add(pw_count.saturating_mul(4)) else {
        return;
    };
    let Some(pw_slice) = data.get(pos..pw_end) else {
        return;
    };
    for suite in pw_slice.as_chunks::<4>().0 {
        if *suite == [0x00, 0x0f, 0xac, 0x02] {
            out.has_tkip = true;
        }
    }
    pos = pw_end;

    let Some(akm_bytes) = data.get(pos..pos + 2) else {
        return;
    };
    let akm_count = usize::from(u16::from_le_bytes([akm_bytes[0], akm_bytes[1]]));
    pos += 2;
    let Some(akm_end) = pos.checked_add(akm_count.saturating_mul(4)) else {
        return;
    };
    let Some(akm_slice) = data.get(pos..akm_end) else {
        return;
    };
    for suite in akm_slice.as_chunks::<4>().0 {
        if suite[..3] == [0x00, 0x0f, 0xac] {
            match suite[3] {
                8 | 9 | 24 => out.has_sae = true,
                2 | 4 | 6 => out.has_psk = true,
                _ => {}
            }
        }
    }
    pos = akm_end;

    if let Some(cap) = data.get(pos..pos + 2) {
        let bits = u16::from_le_bytes([cap[0], cap[1]]);
        out.pmf = Some(if (bits & 0x0040) != 0 {
            "required"
        } else if (bits & 0x0080) != 0 {
            "capable"
        } else {
            "none"
        });
    }
}

/// SSID, channel width (MHz), and security attributes from 802.11 IEs `(id, len, data)*`.
fn parse_ies(ies: &[u8]) -> ParsedIes {
    let mut out = ParsedIes::default();
    let mut off = 0usize;
    while off + 2 <= ies.len() {
        let id = ies[off];
        let len = usize::from(ies[off + 1]);
        let Some(data) = ies.get(off + 2..off + 2 + len) else {
            break;
        };
        match id {
            IE_SSID => {
                if out.ssid.is_none() {
                    out.ssid = ssid_string(data);
                }
            }
            IE_HT_OPERATION => {
                if data.len() >= 2 {
                    let sec_offset = data[1] & 0x03;
                    let w = if sec_offset == 1 || sec_offset == 3 { 40 } else { 20 };
                    out.width_mhz = Some(out.width_mhz.map_or(w, |m| m.max(w)));
                }
            }
            IE_VHT_OPERATION => {
                if data.len() >= 3 {
                    let (cw, ccfs0, ccfs1) = (data[0], data[1], data[2]);
                    let w = match cw {
                        1 => {
                            if ccfs1 != 0 && ccfs1.abs_diff(ccfs0) == 8 {
                                160
                            } else {
                                80
                            }
                        }
                        2 | 3 => 160,
                        _ => 20,
                    };
                    out.width_mhz = Some(out.width_mhz.map_or(w, |m| m.max(w)));
                }
            }
            IE_EXT if data.first() == Some(&IE_EXT_HE_OPERATION) && data.len() >= 7 => {
                let he_params = u32::from_le_bytes([data[1], data[2], data[3], 0]);
                if (he_params & (1 << 17)) != 0 {
                    let mut idx = 7usize;
                    if (he_params & (1 << 14)) != 0 {
                        idx += 3;
                    }
                    if (he_params & (1 << 15)) != 0 {
                        idx += 1;
                    }
                    if let Some(&ctrl) = data.get(idx + 1) {
                        let w = match ctrl & 0x03 {
                            0 => 20,
                            1 => 40,
                            2 => 80,
                            _ => 160,
                        };
                        out.width_mhz = Some(out.width_mhz.map_or(w, |m| m.max(w)));
                    }
                }
            }
            IE_RSN => parse_rsn_ie(data, &mut out),
            IE_VENDOR => {
                if data.starts_with(&[0x00, 0x50, 0xf2, 0x01]) {
                    out.has_wpa1 = true;
                } else if data.starts_with(&[0x00, 0x50, 0xf2, 0x04]) {
                    out.wps = true;
                }
            }
            _ => {}
        }
        off += 2 + len;
    }
    out
}

fn classify_security(ies: &ParsedIes, capability: Option<u16>) -> Option<String> {
    let privacy = capability.is_some_and(|c| (c & 0x0010) != 0);
    let label = if ies.has_sae && ies.has_psk {
        "WPA2/WPA3"
    } else if ies.has_sae {
        "WPA3"
    } else if ies.has_rsn && ies.has_tkip {
        "WPA2-TKIP"
    } else if ies.has_rsn {
        "WPA2"
    } else if ies.has_wpa1 {
        "WPA"
    } else if privacy {
        "WEP"
    } else if capability.is_some() {
        "Open"
    } else {
        return None;
    };
    Some(label.into())
}

fn parse_bss(attrs_buf: &[u8]) -> Result<Option<ScanBss>> {
    let attrs = parse_attrs(attrs_buf)?;
    let Some(bss) = find(&attrs, ATTR_BSS) else {
        return Ok(None);
    };
    let b = bss.nested()?;
    let (Some(bssid), Some(freq)) = (
        find(&b, BSS_BSSID).and_then(|a| mac_string(a.data)),
        find(&b, BSS_FREQUENCY).and_then(|a| a.u32()),
    ) else {
        return Ok(None);
    };
    let ie = find(&b, BSS_INFORMATION_ELEMENTS)
        .map(|a| parse_ies(a.data))
        .unwrap_or_default();
    let bcn = find(&b, BSS_BEACON_IES)
        .map(|a| parse_ies(a.data))
        .unwrap_or_default();
    let width_mhz = match (ie.width_mhz, bcn.width_mhz) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };
    let merged = ParsedIes {
        ssid: ie.ssid.or(bcn.ssid),
        width_mhz,
        has_rsn: ie.has_rsn || bcn.has_rsn,
        has_wpa1: ie.has_wpa1 || bcn.has_wpa1,
        has_sae: ie.has_sae || bcn.has_sae,
        has_psk: ie.has_psk || bcn.has_psk,
        has_tkip: ie.has_tkip || bcn.has_tkip,
        wps: ie.wps || bcn.wps,
        pmf: ie.pmf.or(bcn.pmf),
    };
    let cap = find(&b, BSS_CAPABILITY).and_then(|a| a.u16());
    let security = classify_security(&merged, cap);
    Ok(Some(ScanBss {
        bssid,
        ssid: merged.ssid,
        freq_mhz: freq,
        channel: freq_to_channel(freq),
        width_mhz: merged.width_mhz,
        signal_dbm: find(&b, BSS_SIGNAL_MBM)
            .and_then(|a| a.i32())
            .map(|m| f64::from(m) / 100.0),
        seen_ms_ago: find(&b, BSS_SEEN_MS_AGO).and_then(|a| a.u32()),
        associated: find(&b, BSS_STATUS).and_then(|a| a.u32()) == Some(BSS_STATUS_ASSOCIATED),
        security,
        wps: merged.wps,
        pmf: merged.pmf.map(str::to_string),
    }))
}

/// Utilisation between two surveys of the same frequency.
/// `None` when the frequency differs, a counter is missing or went backwards
/// (driver reset), or no time passed.
pub fn channel_load(prev: &SurveyEntry, cur: &SurveyEntry, iface: &str) -> Option<ChannelLoad> {
    if prev.freq_mhz != cur.freq_mhz {
        return None;
    }
    fn delta(a: Option<u64>, b: Option<u64>) -> Option<Option<u64>> {
        match (a, b) {
            (Some(a), Some(b)) => b.checked_sub(a).map(Some),
            _ => Some(None),
        }
    }
    let interval = delta(prev.active_ms, cur.active_ms)??;
    let busy = delta(prev.busy_ms, cur.busy_ms)??;
    let rx = delta(prev.rx_ms, cur.rx_ms)?;
    let tx = delta(prev.tx_ms, cur.tx_ms)?;
    if interval == 0 {
        return None;
    }
    let pct = |v: u64| (v as f64 * 100.0 / interval as f64).clamp(0.0, 100.0);
    Some(ChannelLoad {
        iface: iface.to_string(),
        freq_mhz: cur.freq_mhz,
        noise_dbm: cur.noise_dbm,
        busy_pct: pct(busy),
        rx_pct: rx.map(pct).unwrap_or(0.0),
        tx_pct: tx.map(pct).unwrap_or(0.0),
        interval_ms: interval,
    })
}

/// IEEE channel number for a centre frequency in the 2.4, 4.9/5 and 6 GHz bands.
pub fn freq_to_channel(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 if (mhz - 2407).is_multiple_of(5) => Some((mhz - 2407) / 5),
        5935 => Some(2),
        5955..=7115 if (mhz - 5950).is_multiple_of(5) => Some((mhz - 5950) / 5),
        4910..=4980 if (mhz - 4000).is_multiple_of(5) => Some((mhz - 4000) / 5),
        5150..=5895 if (mhz - 5000).is_multiple_of(5) => Some((mhz - 5000) / 5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::netlink::tests::nla;
    use super::*;

    fn genl(attrs: &[u8]) -> Vec<u8> {
        [&[0u8, 0, 0, 0][..], attrs].concat()
    }

    #[test]
    fn channels() {
        assert_eq!(freq_to_channel(2412), Some(1));
        assert_eq!(freq_to_channel(2437), Some(6));
        assert_eq!(freq_to_channel(2484), Some(14));
        assert_eq!(freq_to_channel(5180), Some(36));
        assert_eq!(freq_to_channel(5500), Some(100));
        assert_eq!(freq_to_channel(5825), Some(165));
        assert_eq!(freq_to_channel(5955), Some(1));
        assert_eq!(freq_to_channel(6115), Some(33));
        assert_eq!(freq_to_channel(5935), Some(2));
        assert_eq!(freq_to_channel(2413), None);
        assert_eq!(freq_to_channel(0), None);
        assert_eq!(freq_to_channel(60480), None);
    }

    fn survey(t: u64, busy: u64, rx: u64, tx: u64) -> SurveyEntry {
        SurveyEntry {
            freq_mhz: 5180,
            in_use: true,
            noise_dbm: Some(-92),
            active_ms: Some(t),
            busy_ms: Some(busy),
            rx_ms: Some(rx),
            tx_ms: Some(tx),
        }
    }

    #[test]
    fn channel_load_deltas() {
        let l = channel_load(
            &survey(1000, 100, 50, 10),
            &survey(2000, 400, 250, 60),
            "wlo1",
        )
        .unwrap();
        assert_eq!(l.interval_ms, 1000);
        assert!((l.busy_pct - 30.0).abs() < 1e-9);
        assert!((l.rx_pct - 20.0).abs() < 1e-9);
        assert!((l.tx_pct - 5.0).abs() < 1e-9);
        assert_eq!(l.noise_dbm, Some(-92));
        // Counter reset.
        assert!(channel_load(&survey(1000, 100, 50, 10), &survey(500, 50, 10, 1), "w").is_none());
        assert!(
            channel_load(&survey(1000, 100, 50, 10), &survey(2000, 400, 40, 60), "w").is_none()
        );
        // No time passed.
        assert!(
            channel_load(&survey(1000, 100, 50, 10), &survey(1000, 100, 50, 10), "w").is_none()
        );
        // Different channel.
        let mut other = survey(2000, 400, 250, 60);
        other.freq_mhz = 2412;
        assert!(channel_load(&survey(1000, 100, 50, 10), &other, "w").is_none());
        // Missing busy counter.
        let mut nobusy = survey(2000, 0, 0, 0);
        nobusy.busy_ms = None;
        assert!(channel_load(&survey(1000, 100, 50, 10), &nobusy, "w").is_none());
        // Missing rx/tx counters are fine (0 %).
        let mut a = survey(1000, 100, 0, 0);
        let mut b = survey(2000, 200, 0, 0);
        a.rx_ms = None;
        b.tx_ms = None;
        let l = channel_load(&a, &b, "w").unwrap();
        assert_eq!(l.rx_pct, 0.0);
    }

    fn station_bytes() -> Vec<u8> {
        let txrate = [
            nla(RATE_INFO_BITRATE32, &8646u32.to_ne_bytes()),
            nla(RATE_INFO_BITRATE, &1u16.to_ne_bytes()),
        ]
        .concat();
        let rxrate = nla(RATE_INFO_BITRATE, &1200u16.to_ne_bytes());
        let info = [
            nla(STA_INFO_SIGNAL, &[(-55i8) as u8]),
            nla(STA_INFO_SIGNAL_AVG, &[(-57i8) as u8]),
            nla(0x8000 | STA_INFO_TX_BITRATE, &txrate),
            nla(0x8000 | STA_INFO_RX_BITRATE, &rxrate),
            nla(STA_INFO_TX_RETRIES, &12u32.to_ne_bytes()),
            nla(STA_INFO_TX_FAILED, &3u32.to_ne_bytes()),
            nla(STA_INFO_BEACON_LOSS, &0u32.to_ne_bytes()),
            nla(STA_INFO_CONNECTED_TIME, &3600u32.to_ne_bytes()),
        ]
        .concat();
        [
            nla(ATTR_IFINDEX, &3u32.to_ne_bytes()),
            nla(ATTR_MAC, &[0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]),
            nla(0x8000 | ATTR_STA_INFO, &info),
        ]
        .concat()
    }

    #[test]
    fn station_parse() {
        let mut st = WifiStation::default();
        parse_station(&station_bytes(), &mut st).unwrap();
        assert!(st.connected);
        assert_eq!(st.bssid.as_deref(), Some("aa:bb:cc:01:02:03"));
        assert_eq!(st.signal_dbm, Some(-55));
        assert_eq!(st.signal_avg_dbm, Some(-57));
        assert_eq!(st.tx_bitrate_mbps, Some(864.6));
        assert_eq!(st.rx_bitrate_mbps, Some(120.0));
        assert_eq!(st.tx_retries, Some(12));
        assert_eq!(st.tx_failed, Some(3));
        assert_eq!(st.connected_s, Some(3600));
        // genl helper keeps the header skip consistent.
        let full = genl(&station_bytes());
        let mut st2 = WifiStation::default();
        parse_station(genl_payload(&full), &mut st2).unwrap();
        assert_eq!(st, st2);
    }

    #[test]
    fn station_truncated_is_error_not_panic() {
        let b = station_bytes();
        for cut in 1..b.len() {
            let mut st = WifiStation::default();
            let _ = parse_station(&b[..cut], &mut st);
        }
        let mut st = WifiStation::default();
        assert!(parse_station(&b[..b.len() - 3], &mut st).is_err());
        let mut none = WifiStation::default();
        parse_station(&nla(ATTR_IFINDEX, &3u32.to_ne_bytes()), &mut none).unwrap();
        assert!(!none.connected);
    }

    #[test]
    fn interface_parse() {
        let b = [
            nla(ATTR_SSID, b"HomeNet"),
            nla(ATTR_WIPHY_FREQ, &5180u32.to_ne_bytes()),
            nla(ATTR_CHANNEL_WIDTH, &3u32.to_ne_bytes()),
        ]
        .concat();
        assert_eq!(
            parse_interface(&b).unwrap(),
            IfaceInfo {
                ssid: Some("HomeNet".into()),
                freq_mhz: Some(5180),
                width_mhz: Some(80)
            }
        );
        let hidden = nla(ATTR_SSID, &[0, 0, 0]);
        assert_eq!(parse_interface(&hidden).unwrap().ssid, None);
    }

    #[test]
    fn survey_parse() {
        let info = [
            nla(SURVEY_INFO_FREQUENCY, &5180u32.to_ne_bytes()),
            nla(SURVEY_INFO_NOISE, &[(-95i8) as u8]),
            nla(SURVEY_INFO_IN_USE, &[]),
            nla(SURVEY_INFO_TIME, &123456u64.to_ne_bytes()),
            nla(SURVEY_INFO_TIME_BUSY, &2345u64.to_ne_bytes()),
            nla(SURVEY_INFO_TIME_RX, &1000u64.to_ne_bytes()),
            nla(SURVEY_INFO_TIME_TX, &200u32.to_ne_bytes()),
        ]
        .concat();
        let b = [
            nla(ATTR_IFINDEX, &3u32.to_ne_bytes()),
            nla(0x8000 | ATTR_SURVEY_INFO, &info),
        ]
        .concat();
        let e = parse_survey(&b).unwrap().unwrap();
        assert_eq!(e.freq_mhz, 5180);
        assert!(e.in_use);
        assert_eq!(e.noise_dbm, Some(-95));
        assert_eq!(e.active_ms, Some(123456));
        assert_eq!(e.busy_ms, Some(2345));
        assert_eq!(e.tx_ms, Some(200));
        // Entry without frequency is skipped; without SURVEY_INFO too.
        let nofreq = nla(ATTR_SURVEY_INFO, &nla(SURVEY_INFO_NOISE, &[1]));
        assert_eq!(parse_survey(&nofreq).unwrap(), None);
        assert_eq!(parse_survey(&[]).unwrap(), None);
        // Nested attr with bad inner length.
        let bad = nla(ATTR_SURVEY_INFO, &[200, 0, 1, 0, 0, 0, 0, 0]);
        assert!(parse_survey(&bad).is_err());
    }

    #[test]
    fn in_use_fallback() {
        let mut v = vec![survey(1, 0, 0, 0), survey(1, 0, 0, 0)];
        v[0].in_use = false;
        v[1].in_use = false;
        v[1].freq_mhz = 5500;
        mark_in_use(&mut v, Some(5500));
        assert!(!v[0].in_use && v[1].in_use);
        v[1].in_use = false;
        mark_in_use(&mut v, Some(2412));
        assert!(!v.iter().any(|e| e.in_use));
        v[0].in_use = true;
        mark_in_use(&mut v, Some(5500));
        assert!(!v[1].in_use, "driver flag wins");
    }

    #[test]
    fn ie_parse() {
        let ies = [&[1u8, 2, 0x82, 0x84][..], &[0, 4], b"Caf\xE9".as_ref()].concat();
        let p = parse_ies(&ies);
        assert_eq!((p.ssid.as_deref(), p.width_mhz), (Some("Caf\u{fffd}"), None));
        assert_eq!(parse_ies(&[0, 3, b'a', b'b', b'c']).ssid.as_deref(), Some("abc"));
        assert_eq!(parse_ies(&[0, 0]).ssid, None, "hidden");
        assert_eq!(parse_ies(&[0, 9, b'a']).ssid, None, "truncated");
        assert_eq!(parse_ies(&[1, 200]).ssid, None);
        assert_eq!(parse_ies(&[]).ssid, None);

        // HT Operation (61): sec channel offset = 1 -> 40 MHz
        let mut ht40 = vec![0u8; 22];
        ht40[0] = 6;
        ht40[1] = 1;
        let ies_ht40 = [&[0u8, 2, b'h', b't'][..], &[IE_HT_OPERATION, ht40.len() as u8], &ht40].concat();
        let p = parse_ies(&ies_ht40);
        assert_eq!((p.ssid.as_deref(), p.width_mhz), (Some("ht"), Some(40)));

        // VHT Operation (192): cw=1, ccfs0=42, ccfs1=0 -> 80 MHz
        let ies_vht80 = [&ies_ht40[..], &[IE_VHT_OPERATION, 5, 1, 42, 0, 0, 0]].concat();
        assert_eq!(parse_ies(&ies_vht80).width_mhz, Some(80));

        // VHT Operation (192): cw=1, ccfs0=42, ccfs1=50 (diff=8) -> 160 MHz
        let ies_vht160 = [&ies_ht40[..], &[IE_VHT_OPERATION, 5, 1, 42, 50, 0, 0]].concat();
        assert_eq!(parse_ies(&ies_vht160).width_mhz, Some(160));

        // VHT Operation (192): cw=2 -> 160 MHz
        let ies_vht160_cw2 = [IE_VHT_OPERATION, 5, 2, 50, 0, 0, 0];
        assert_eq!(parse_ies(&ies_vht160_cw2).width_mhz, Some(160));
    }

    #[test]
    fn ie_security_parse() {
        // RSN IE: version=1, group=AES, 1 pairwise AES, 2 AKMs (PSK + SAE), RSN cap=MFPR|MFPC (0x00c0)
        let rsn = [
            IE_RSN, 24,
            1, 0,
            0x00, 0x0f, 0xac, 4,
            1, 0, 0x00, 0x0f, 0xac, 4,
            2, 0, 0x00, 0x0f, 0xac, 2, 0x00, 0x0f, 0xac, 8,
            0xc0, 0x00,
        ];
        let wps = [IE_VENDOR, 4, 0x00, 0x50, 0xf2, 0x04];
        let both = [&rsn[..], &wps[..]].concat();
        let p = parse_ies(&both);
        assert_eq!(classify_security(&p, Some(0x0010)).as_deref(), Some("WPA2/WPA3"));
        assert_eq!(p.pmf, Some("required"));
        assert!(p.wps);

        let tkip = [IE_RSN, 14, 1, 0, 0, 0x0f, 0xac, 2, 1, 0, 0, 0x0f, 0xac, 2, 0, 0];
        let mut bad_tkip = tkip;
        bad_tkip[1] = 14;
        let pt = parse_ies(&bad_tkip);
        assert_eq!(classify_security(&pt, Some(0x0010)).as_deref(), Some("WPA2-TKIP"));
        assert_eq!(classify_security(&ParsedIes::default(), Some(0x0010)).as_deref(), Some("WEP"));
        assert_eq!(classify_security(&ParsedIes::default(), Some(0x0001)).as_deref(), Some("Open"));

        // Truncated RSN must never panic.
        let _ = parse_ies(&[IE_RSN, 3, 1, 0, 0]);
    }

    #[test]
    fn bss_parse() {
        let ies = [&[0u8, 5][..], b"Neigh", &[3, 1, 36]].concat();
        let inner = [
            nla(BSS_BSSID, &[1, 2, 3, 4, 5, 6]),
            nla(BSS_FREQUENCY, &5180u32.to_ne_bytes()),
            nla(BSS_INFORMATION_ELEMENTS, &ies),
            nla(BSS_SIGNAL_MBM, &(-6700i32).to_ne_bytes()),
            nla(BSS_STATUS, &BSS_STATUS_ASSOCIATED.to_ne_bytes()),
            nla(BSS_SEEN_MS_AGO, &250u32.to_ne_bytes()),
        ]
        .concat();
        let b = nla(0x8000 | ATTR_BSS, &inner);
        let r = parse_bss(&b).unwrap().unwrap();
        assert_eq!(r.bssid, "01:02:03:04:05:06");
        assert_eq!(r.ssid.as_deref(), Some("Neigh"));
        assert_eq!(r.channel, Some(36));
        assert_eq!(r.signal_dbm, Some(-67.0));
        assert_eq!(r.seen_ms_ago, Some(250));
        assert!(r.associated);
        for cut in 1..b.len() {
            let _ = parse_bss(&b[..cut]);
        }
        let short_mac = nla(
            ATTR_BSS,
            &[
                nla(BSS_BSSID, &[1, 2]),
                nla(BSS_FREQUENCY, &2412u32.to_ne_bytes()),
            ]
            .concat(),
        );
        assert_eq!(parse_bss(&short_mac).unwrap(), None);
    }

    /// Prints live data from wlo1 (no scan trigger unless permitted).
    #[test]
    #[ignore = "needs real Wi-Fi hardware (wlo1)"]
    fn real_nl80211_wlo1() {
        let mut nl = Nl80211::open().expect("open nl80211");
        let st = nl.station("wlo1").expect("station");
        println!("station: {st:#?}");
        assert!(st.connected);
        let s1 = nl.survey("wlo1").expect("survey");
        println!("survey entries: {}", s1.len());
        for e in s1
            .iter()
            .filter(|e| e.in_use || e.active_ms.unwrap_or(0) > 0)
        {
            println!("  {e:?}");
        }
        std::thread::sleep(Duration::from_secs(2));
        let s2 = nl.survey("wlo1").expect("survey 2");
        if let (Some(a), Some(b)) = (s1.iter().find(|e| e.in_use), s2.iter().find(|e| e.in_use)) {
            println!("channel load: {:?}", channel_load(a, b, "wlo1"));
        } else {
            println!("no in-use survey entry");
        }
        match nl.trigger_scan("wlo1") {
            Ok(()) => println!("trigger_scan: ok"),
            Err(e) => println!("trigger_scan: {e:#}"),
        }
        let bss = nl.scan_results("wlo1").expect("scan results");
        println!("scan results: {}", bss.len());
        for b in bss.iter().take(10) {
            println!("  {b:?}");
        }
        assert!(nl.station("nosuchif0").is_err());
    }

    #[test]
    fn power_save_and_mlme_parse() {
        assert_eq!(
            parse_power_save(&nla(ATTR_PS_STATE, &PS_ENABLED.to_ne_bytes())).unwrap(),
            Some(true)
        );
        assert_eq!(
            parse_power_save(&nla(ATTR_PS_STATE, &PS_DISABLED.to_ne_bytes())).unwrap(),
            Some(false)
        );
        assert_eq!(parse_power_save(&[]).unwrap(), None);

        let disc_attrs = [
            nla(ATTR_IFINDEX, &4u32.to_ne_bytes()),
            nla(ATTR_MAC, &[0x02, 0, 0, 0, 0, 1]),
            nla(ATTR_REASON_CODE, &4u16.to_ne_bytes()),
            nla(ATTR_DISCONNECTED_BY_AP, &[]),
        ]
        .concat();
        let disc_payload = [&[CMD_DISCONNECT, 0, 0, 0][..], &disc_attrs].concat();
        let ev = parse_mlme_msg(41, netlink::Msg { ty: 41, flags: 0, seq: 0, payload: &disc_payload }).unwrap();
        assert_eq!(
            ev,
            MlmeEvent::Disconnect {
                ifindex: 4,
                bssid: Some("02:00:00:00:00:01".into()),
                reason_code: Some(4),
                by_ap: Some(true),
                timed_out: false,
            }
        );

        // 802.11 Deauth frame (type=0, subtype=0xc => 0xc0): SA == BSSID => by_ap=Some(true), reason=7
        let mut frame = vec![0u8; 26];
        frame[0] = 0xc0;
        frame[10..16].copy_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        frame[16..22].copy_from_slice(&[0x02, 0, 0, 0, 0, 9]);
        frame[24..26].copy_from_slice(&7u16.to_le_bytes());
        let deauth_attrs = [nla(ATTR_IFINDEX, &5u32.to_ne_bytes()), nla(ATTR_FRAME, &frame)].concat();
        let deauth_payload = [&[CMD_DEAUTHENTICATE, 0, 0, 0][..], &deauth_attrs].concat();
        assert_eq!(
            parse_mlme_msg(41, netlink::Msg { ty: 41, flags: 0, seq: 0, payload: &deauth_payload }),
            Some(MlmeEvent::Disconnect {
                ifindex: 5,
                bssid: Some("02:00:00:00:00:09".into()),
                reason_code: Some(7),
                by_ap: Some(true),
                timed_out: false,
            })
        );

        let cs_attrs = [nla(ATTR_IFINDEX, &4u32.to_ne_bytes()), nla(ATTR_WIPHY_FREQ, &5260u32.to_ne_bytes())].concat();
        let cs_payload = [&[CMD_CH_SWITCH_NOTIFY, 0, 0, 0][..], &cs_attrs].concat();
        assert_eq!(
            parse_mlme_msg(41, netlink::Msg { ty: 41, flags: 0, seq: 0, payload: &cs_payload }),
            Some(MlmeEvent::ChannelSwitch { ifindex: 4, freq_mhz: 5260 })
        );

        // Wrong family or truncated payload must return None, never panic.
        assert_eq!(parse_mlme_msg(99, netlink::Msg { ty: 41, flags: 0, seq: 0, payload: &cs_payload }), None);
        assert_eq!(parse_mlme_msg(41, netlink::Msg { ty: 41, flags: 0, seq: 0, payload: &[CMD_DISCONNECT] }), None);
    }
}
