# Readiness advisor

The advisor tells the user what spoils which conclusion. It does not list every setting.

## Rules

1. Say something only when it changes a conclusion. Every item names the question it spoils
   (for example "Wi-Fi vs router/ISP separation").
2. Show one top action first. Group the other items below it.
3. Every item shows its evidence and its threshold.
4. Never repeat. During a run, report a condition once per session when it starts and once when
   it clears. If it comes back in the same session, stay silent. An item disappears when its
   condition clears.
5. The user can accept a risk: `[advisor] accept = ["no_wired_path"]`. An accepted risk is silent.
   Blocking items cannot be accepted. An unknown code is a config error.

## Phase 1: `linkwatch check`

`check` prints its item lines, then a readiness block. `check::Item.code` is the stable code;
`src/readiness.rs` maps codes to rules. Levels: `GO`, `GO WITH CAVEATS`, `NO-GO` (a blocking item
failed). The exit code is unchanged: 1 only when an item is FAIL.

| Code | Spoils | Level |
| --- | --- | --- |
| icmp_permission | every probe | blocking (FAIL) |
| data_dir | recording | blocking (FAIL) |
| wifi_blocked | the Wi-Fi path | blocking (FAIL) |
| path_isolation | Wi-Fi vs Ethernet separation (rp_filter, ARP flux, path proof) | blocking (FAIL) |
| no_wired_path | Wi-Fi vs router/ISP separation | caveat |
| vpn_active | ISP and internet verdicts | caveat |
| clock_unsynced | cross-device compare, router-log matching | caveat |
| wifi_power_save | latency numbers | caveat |
| bluetooth_24ghz | Wi-Fi latency numbers | caveat |
| timer_jitter | latency numbers (`--deep`) | caveat |
| host_pressure | latency and loss (`--deep`, PSI) | caveat |
| conntrack_full | loss figures | caveat |
| two_net_managers | link-drop causes | caveat |
| random_mac | router device counts, DHCP/ARP stability | caveat |
| clock_loose | tight cross-device alignment | caveat |
| disk_low | run length | caveat |

## Phase 2: during a run

The host loop reports two conditions: Wi-Fi power-save turned on (`host_alert wifi_power_save`)
and loss of NTP sync (`host_alert clock_unsynced`). A clear is a `note` that starts with
`advisor: `. When `[alerts]` is enabled, each edge is also sent to the notifier with its own
key (`advisor:<code>:<iface>`).
