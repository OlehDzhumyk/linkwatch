//! Numeric constants from `<linux/nl80211.h>` (stable kernel UAPI).
//! Only the values this crate uses; names follow the header.

// enum nl80211_commands
/// NL80211_CMD_GET_INTERFACE
pub const CMD_GET_INTERFACE: u8 = 5;
/// NL80211_CMD_GET_STATION
pub const CMD_GET_STATION: u8 = 17;
/// NL80211_CMD_GET_SCAN
pub const CMD_GET_SCAN: u8 = 32;
/// NL80211_CMD_GET_REG
pub const CMD_GET_REG: u8 = 31;
/// NL80211_CMD_TRIGGER_SCAN
pub const CMD_TRIGGER_SCAN: u8 = 33;
/// NL80211_CMD_GET_SURVEY
pub const CMD_GET_SURVEY: u8 = 50;
/// NL80211_CMD_DEAUTHENTICATE
pub const CMD_DEAUTHENTICATE: u8 = 39;
/// NL80211_CMD_DISASSOCIATE
pub const CMD_DISASSOCIATE: u8 = 40;
/// NL80211_CMD_DISCONNECT
pub const CMD_DISCONNECT: u8 = 48;
/// NL80211_CMD_GET_POWER_SAVE
pub const CMD_GET_POWER_SAVE: u8 = 62;
/// NL80211_CMD_CH_SWITCH_NOTIFY
pub const CMD_CH_SWITCH_NOTIFY: u8 = 88;
/// NL80211_CMD_CONN_FAILED
pub const CMD_CONN_FAILED: u8 = 91;

// enum nl80211_attrs
/// NL80211_ATTR_IFINDEX (u32)
pub const ATTR_IFINDEX: u16 = 3;
/// NL80211_ATTR_WIPHY (u32)
pub const ATTR_WIPHY: u16 = 1;
/// NL80211_ATTR_REG_ALPHA2 (string, ISO 3166 country or "00" world)
pub const ATTR_REG_ALPHA2: u16 = 33;
/// NL80211_ATTR_MAC (6 bytes)
pub const ATTR_MAC: u16 = 6;
/// NL80211_ATTR_STA_INFO (nested, enum nl80211_sta_info)
pub const ATTR_STA_INFO: u16 = 21;
/// NL80211_ATTR_WIPHY_FREQ (u32, MHz)
pub const ATTR_WIPHY_FREQ: u16 = 38;
/// NL80211_ATTR_BSS (nested, enum nl80211_bss)
pub const ATTR_BSS: u16 = 47;
/// NL80211_ATTR_FRAME (binary 802.11 frame)
pub const ATTR_FRAME: u16 = 51;
/// NL80211_ATTR_SSID (binary, up to 32 bytes)
pub const ATTR_SSID: u16 = 52;
/// NL80211_ATTR_REASON_CODE (u16)
pub const ATTR_REASON_CODE: u16 = 54;
/// NL80211_ATTR_TIMED_OUT (flag)
pub const ATTR_TIMED_OUT: u16 = 65;
/// NL80211_ATTR_DISCONNECTED_BY_AP (flag)
pub const ATTR_DISCONNECTED_BY_AP: u16 = 71;
/// NL80211_ATTR_SURVEY_INFO (nested, enum nl80211_survey_info)
pub const ATTR_SURVEY_INFO: u16 = 84;
/// NL80211_ATTR_PS_STATE (u32, enum nl80211_ps_state)
pub const ATTR_PS_STATE: u16 = 93;
/// NL80211_ATTR_CHANNEL_WIDTH (u32, enum nl80211_chan_width)
pub const ATTR_CHANNEL_WIDTH: u16 = 159;

// enum nl80211_ps_state
pub const PS_DISABLED: u32 = 0;
pub const PS_ENABLED: u32 = 1;

/// Short human-readable IEEE 802.11 disconnect/deauth reason name.
pub fn reason_name(code: u16) -> &'static str {
    match code {
        1 => "unspecified",
        2 => "previous_auth_invalid",
        3 => "leaving_network",
        4 => "inactivity",
        5 => "ap_overloaded",
        6 | 7 => "not_authenticated",
        8 => "leaving_bss",
        9 => "not_associated",
        10 | 11 => "unacceptable_power_cap",
        13 | 14 => "invalid_ie_or_mic",
        15 => "4way_handshake_timeout",
        16 => "group_key_timeout",
        17..=23 => "auth_or_ie_failure",
        24 => "cipher_rejected",
        32..=39 => "qos_or_bandwidth",
        _ => "unknown",
    }
}

// enum nl80211_sta_info
/// NL80211_STA_INFO_SIGNAL (u8, signed dBm)
pub const STA_INFO_SIGNAL: u16 = 7;
/// NL80211_STA_INFO_TX_BITRATE (nested, enum nl80211_rate_info)
pub const STA_INFO_TX_BITRATE: u16 = 8;
/// NL80211_STA_INFO_TX_RETRIES (u32)
pub const STA_INFO_TX_RETRIES: u16 = 11;
/// NL80211_STA_INFO_TX_FAILED (u32)
pub const STA_INFO_TX_FAILED: u16 = 12;
/// NL80211_STA_INFO_SIGNAL_AVG (u8, signed dBm)
pub const STA_INFO_SIGNAL_AVG: u16 = 13;
/// NL80211_STA_INFO_RX_BITRATE (nested, enum nl80211_rate_info)
pub const STA_INFO_RX_BITRATE: u16 = 14;
/// NL80211_STA_INFO_CONNECTED_TIME (u32, seconds)
pub const STA_INFO_CONNECTED_TIME: u16 = 16;
/// NL80211_STA_INFO_BEACON_LOSS (u32)
pub const STA_INFO_BEACON_LOSS: u16 = 18;

// enum nl80211_rate_info
/// NL80211_RATE_INFO_BITRATE (u16, 100 kbit/s)
pub const RATE_INFO_BITRATE: u16 = 1;
/// NL80211_RATE_INFO_BITRATE32 (u32, 100 kbit/s)
pub const RATE_INFO_BITRATE32: u16 = 5;

// enum nl80211_survey_info
/// NL80211_SURVEY_INFO_FREQUENCY (u32, MHz)
pub const SURVEY_INFO_FREQUENCY: u16 = 1;
/// NL80211_SURVEY_INFO_NOISE (u8, signed dBm)
pub const SURVEY_INFO_NOISE: u16 = 2;
/// NL80211_SURVEY_INFO_IN_USE (flag)
pub const SURVEY_INFO_IN_USE: u16 = 3;
/// NL80211_SURVEY_INFO_TIME (u64, ms)
pub const SURVEY_INFO_TIME: u16 = 4;
/// NL80211_SURVEY_INFO_TIME_BUSY (u64, ms)
pub const SURVEY_INFO_TIME_BUSY: u16 = 5;
/// NL80211_SURVEY_INFO_TIME_RX (u64, ms)
pub const SURVEY_INFO_TIME_RX: u16 = 7;
/// NL80211_SURVEY_INFO_TIME_TX (u64, ms)
pub const SURVEY_INFO_TIME_TX: u16 = 8;

// enum nl80211_bss
/// NL80211_BSS_BSSID (6 bytes)
pub const BSS_BSSID: u16 = 1;
/// NL80211_BSS_FREQUENCY (u32, MHz)
pub const BSS_FREQUENCY: u16 = 2;
/// NL80211_BSS_CAPABILITY (u16)
pub const BSS_CAPABILITY: u16 = 5;
/// NL80211_BSS_INFORMATION_ELEMENTS (binary IEs)
pub const BSS_INFORMATION_ELEMENTS: u16 = 6;
/// NL80211_BSS_SIGNAL_MBM (s32, 100 * dBm)
pub const BSS_SIGNAL_MBM: u16 = 7;
/// NL80211_BSS_STATUS (u32, enum nl80211_bss_status)
pub const BSS_STATUS: u16 = 9;
/// NL80211_BSS_SEEN_MS_AGO (u32)
pub const BSS_SEEN_MS_AGO: u16 = 10;
/// NL80211_BSS_BEACON_IES (binary IEs)
pub const BSS_BEACON_IES: u16 = 11;

// enum nl80211_bss_status
/// NL80211_BSS_STATUS_ASSOCIATED
pub const BSS_STATUS_ASSOCIATED: u32 = 1;

/// MHz of an `enum nl80211_chan_width` value.
pub fn chan_width_mhz(w: u32) -> Option<u32> {
    Some(match w {
        0 | 1 => 20, // NL80211_CHAN_WIDTH_20_NOHT, _20
        2 => 40,     // _40
        3 => 80,     // _80
        4 => 160,    // _80P80 (total)
        5 => 160,    // _160
        6 => 5,      // _5
        7 => 10,     // _10
        8 => 1,      // _1 (S1G)
        9 => 2,      // _2
        10 => 4,     // _4
        11 => 8,     // _8
        12 => 16,    // _16
        13 => 320,   // _320
        _ => return None,
    })
}

/// 802.11 information element id of the SSID.
pub const IE_SSID: u8 = 0;
/// 802.11 HT Operation IE id.
pub const IE_HT_OPERATION: u8 = 61;
/// 802.11 VHT Operation IE id.
pub const IE_VHT_OPERATION: u8 = 192;
/// 802.11 Extension IE id.
pub const IE_EXT: u8 = 255;
/// 802.11 RSN (WPA2/WPA3) IE id.
pub const IE_RSN: u8 = 48;
/// 802.11 Vendor Specific IE id (WPA1 / WPS).
pub const IE_VENDOR: u8 = 221;
/// 802.11 HE Operation extension IE id.
pub const IE_EXT_HE_OPERATION: u8 = 36;
