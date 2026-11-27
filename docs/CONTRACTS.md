# linkwatch module contracts

Linux-only network path monitor. Targets x86_64 and aarch64 (Raspberry Pi), static musl builds.
Shared types: `src/model.rs`, `src/config.rs`, `src/live.rs` (owned by the coordinator, do not edit;
ask in your report if you need a change).

Rules for every module:
- No panics on bad input from the kernel, network, disk or files. Return errors or "fail" results.
- No `unwrap()`/`expect()` outside tests, except on values proven valid in the same function.
- No shelling out to `ping`, `iw`, `ip`, `curl`. Use sockets, netlink, sysfs, procfs.
- Async code uses tokio. Blocking syscalls longer than ~1 ms go through `spawn_blocking`
  or non-blocking sockets with `AsyncFd`.
- Every timeout is explicit. Nothing may hang forever.
- Pure-Rust dependency stack: tokio(full), serde, serde_json, toml, anyhow, thiserror,
  tracing, tracing-subscriber, socket2(all), libc, netlink-sys, nix, clap, futures, chrono,
  axum 0.7, flate2, fd-lock, sd-notify, uuid, tokio-stream, md-5, rustls, rustls-rustcrypto,
  snmp2 (crypto-rust), tokio-rustls, webpki-roots (+ tempfile, ts-rs in dev). Zero C toolchain
  needed for cross-compiled musl builds.
- Unit tests for parsers and state logic. Mark tests that need real network/root with `#[ignore]`.

## Agent A: measurement (`src/probe/`, `src/link.rs`, `src/wifi/`, `src/speed.rs`)

```rust
// src/probe/icmp.rs  — unprivileged ICMP (SOCK_DGRAM, IPPROTO_ICMP), bound to interface
// with SO_BINDTODEVICE. Verify reply type, sequence and a random payload token;
// ignore foreign/duplicate replies; reply after timeout => fail("timeout").
pub async fn ping(iface: &str, dst: Ipv4Addr, timeout: Duration) -> ProbeResult;
// Optional TTL-limited probe used for ISP-hop discovery (IP_TTL + IP_RECVERR / MSG_ERRQUEUE):
pub async fn probe_ttl(iface: &str, dst: Ipv4Addr, ttl: u8, timeout: Duration) -> Option<Ipv4Addr>; // responder addr

// src/probe/tcp.rs — TCP connect bound to interface; refused counts as ok (host reachable).
pub async fn connect(iface: &str, dst: SocketAddr, timeout: Duration) -> ProbeResult;

// src/probe/dns.rs — minimal hand-built DNS A query over UDP bound to interface.
pub async fn query(iface: &str, server: Ipv4Addr, name: &str, timeout: Duration) -> ProbeResult;

// src/probe/mod.rs
pub mod icmp; pub mod tcp; pub mod dns;
/// First hop after the gateway that is not private-LAN (walk TTL 2..=4 towards 1.1.1.1).
pub async fn discover_isp_hop(iface: &str, gateway: Ipv4Addr, timeout: Duration) -> Option<Ipv4Addr>;

// src/link.rs — sysfs/procfs/getifaddrs, synchronous and cheap.
pub fn read(iface: &str) -> LinkState;            // never panics; missing iface => present=false
pub fn detect_role(iface: &str) -> IfaceRole;      // /sys/class/net/<if>/wireless or phy80211 => Wifi
pub fn list_candidates() -> Vec<(String, IfaceRole)>; // physical ifaces, skip lo/docker/veth/br/tun
pub fn resolv_conf_servers() -> Vec<Ipv4Addr>;      // skip 127.0.0.0/8; also read /run/systemd/resolve/resolv.conf

// src/wifi/ — nl80211 over generic netlink, hand-written (libc netlink socket + TLV parsing).
pub struct Nl80211 { /* socket, family id */ }
impl Nl80211 {
    pub fn open() -> anyhow::Result<Self>;
    pub fn station(&mut self, iface: &str) -> anyhow::Result<WifiStation>;   // connected=false if not associated
    pub fn survey(&mut self, iface: &str) -> anyhow::Result<Vec<SurveyEntry>>;
    pub fn trigger_scan(&mut self, iface: &str) -> anyhow::Result<()>;       // EPERM => Err with clear message
    pub fn scan_results(&mut self, iface: &str) -> anyhow::Result<Vec<ScanBss>>;
}
pub fn channel_load(prev: &SurveyEntry, cur: &SurveyEntry, iface: &str) -> Option<ChannelLoad>; // handles counter reset
pub fn freq_to_channel(mhz: u32) -> Option<u32>;  // 2.4, 5, 6 GHz

// src/speed.rs — plain HTTP/1.1 GET over a TCP socket bound to the interface; counts body bytes,
// stops at max_bytes or timeout; handles Content-Length, chunked, redirects (max 3, http only),
// non-200 => err. Tries urls in order until one gives a result.
pub async fn download(iface: &str, urls: &[String], max_bytes: u64, timeout: Duration) -> SpeedResult;
```

## Agent B: storage, site layout, web (`src/store/`, `src/site.rs`, `src/web/`)

```rust
// src/store/ — JSONL writer. Single task owns all files.
pub struct StoreHandle { pub tx: tokio::sync::mpsc::Sender<Record>, /* ... */ }
/// Creates/opens <data_dir>/<session>/, takes an exclusive lock (<data_dir>/.lock, fail if held),
/// writes meta.json, continues `seq` after the last valid line of existing files,
/// truncates a partial last line (crash recovery), returns gap since last heartbeat file.
pub async fn open(data_dir: &Path, meta: SessionMeta, cfg: &config::Storage, live: Live)
    -> anyhow::Result<(StoreHandle, OpenInfo)>;
pub struct OpenInfo { pub gap_s: Option<f64>, pub prev_boot_id: Option<String>, pub next_seq: u64 }
impl StoreHandle {
    /// Never blocks: try_send; on full queue count drops and emit Event::DroppedRecords later.
    pub fn send(&self, rec: Record);
    /// Flush, fsync, write summary.json, close. Called on shutdown.
    pub async fn close(self, summary: serde_json::Value) -> anyhow::Result<()>;
}
// File layout per session dir:
//   meta.json, <stream>-YYYYMMDD.jsonl (UTC day; streams: samples, events, wifi, speed),
//   previous days gzip-compressed (<name>.jsonl.gz) in background, heartbeat (atomic rename),
//   summary.json.
// Each line = serde_json of model::Envelope. Writer assigns seq, ts, mono_ns.
// Also: broadcast every Envelope to live.feed, keep live.events ring (EVENTS_KEPT) for Event records.
// Disk pressure: statvfs; < min_free => drop samples (keep events), emit DiskPressure once per mode change;
//   < critical => write nothing, log via tracing.
// fsync every cfg.fsync_s. IO errors: retry with backoff, never panic, count drops.

pub mod read {
    /// Iterate envelopes of a stream in a session dir across days (.jsonl and .jsonl.gz),
    /// skipping malformed lines (count them). Used by web history and `report`.
    pub fn iter(session_dir: &Path, stream: Stream) -> impl Iterator<Item = Envelope>;
    pub fn sessions(data_dir: &Path) -> Vec<(PathBuf, SessionMeta)>;
}

// src/site.rs — optional site model (no hard-coded buildings/rooms).
// TOML: unit types (reusable layouts in metres, rooms as polygons/rects, walls with materials,
// doors with swing/kind, fixed areas, named points), buildings with units (type, floor, label),
// vertical neighbor resolution (above/below), and measurement [[plan]] entries.
// Point id = "<building>/<unit>/<point>", e.g. "B1/F2/R3"; a room id doubles as a point at its centroid.
pub struct Site { ... }
impl Site {
    pub fn load(path: &Path) -> anyhow::Result<Site>;   // validation with clear errors
    pub fn point(&self, id: &str) -> Option<ResolvedPoint>;
    pub fn estimate_rf(&self, target_point_id: &str) -> Option<RfPathEstimate>;
}
// examples/site.toml: a small fictional layout (two blocks, explicit right/left unit types, walls/doors);
// real site files stay outside the repository.

// src/web/ — axum 0.7 server, static UI embedded with include_str! (no CDN, strict CSP, works offline).
pub async fn serve(listen: SocketAddr, live: Live, data_dir: PathBuf, site: Option<Arc<Site>>,
                   token: Option<String>, control: Option<ControlHandle>,
                   shutdown: impl Future<Output = ()> + Send + 'static) -> anyhow::Result<()>;
pub async fn serve_with_router(..., opts: WebRouterOpts, shutdown: ...) -> anyhow::Result<()>;
// API (JSON / downloads):
//   GET  /api/status, /api/minutes?iface=&hours=|minutes=&session=, /api/events?limit=,
//        /api/speed, /api/scan, /api/site, /api/plan, /api/sessions, /api/report?session=,
//        /api/report/export?session=&format=md|json, /api/compare?sessions=...&tolerance_s=&format=json|md,
//        /api/sessions/:id/summary, /api/sessions/:id/events, /api/live (SSE),
//        /api/control, /api/router/audit, /api/advice
//   POST /api/control/session, /api/router/probe, /api/router/cve
//        (POST mutations require [web] token + SameOrigin + application/json + rate limit)
// UI: 4-tab layout (Live, Map & Plan, Wi-Fi, System), dark/light auto theme, extensible i18n (EN/UK), interactive tooltips.
// Web bind failure (port in use) => log error, monitor keeps running.
```

## Extensions: router telemetry, LAN sweep, router audit, CVE lookup, advisor & alerts

```rust
// src/router.rs — read-only UPnP IGDv1/IGDv2 SOAP poller (SSDP gateway-only or explicit URL).
pub struct Poller { /* ... */ }
pub fn parse_http_url(url: &str) -> anyhow::Result<HttpUrl>;
pub fn ssdp_location(resp: &str, gateway: Ipv4Addr) -> Option<String>;
pub fn parse_igd_xml(xml: &str, base: &HttpUrl) -> IgdEndpoints;
pub fn counter_delta(prev: u64, cur: u64, dt_s: f64, max_rate: f64) -> CounterDelta;

// src/lan.rs — privacy-preserving LAN device count (/22..=/30, counts only; hashed MACs in RAM).
pub async fn count(...) -> LanCount;
pub struct DeviceCounter { /* salted HashSet<u64>, MAX_SEEN = 4096 */ }

// src/router_audit.rs — modular read-only adapters (upnp, snmp + IF-MIB, tr064, openwrt, mikrotik, http) + port check.
pub fn validate_local_host(raw: &str) -> anyhow::Result<Ipv4Addr>; // private/loopback/link-local only
pub async fn probe_gateway_ports(gw: Ipv4Addr) -> Vec<PortCheck>;
pub async fn run_probe(gw: Ipv4Addr, gw_mac: Option<String>, req: &RouterProbeRequest, upnp_url: Option<&str>) -> RouterAudit;

// src/cve.rs — on-demand pure-Rust TLS lookup (CIRCL -> NIST NVD 2.0 + CISA KEV + offline bundle), CPE normalization, 24 h cache.
pub fn normalize_device_query(vendor: Option<&str>, model: &str) -> (Option<String>, String);
pub fn version_lt(a: &str, b: &str) -> Option<bool>;
pub async fn lookup_cves(data_dir: &Path, req: &CveLookupRequest, nvd_api_key: Option<&str>) -> anyhow::Result<CveLookupResponse>;

// src/advice.rs — rule-based Wi-Fi, security, router & observer health recommendations.
pub fn evaluate(snap: &LiveSnapshot, audit: Option<&RouterAudit>) -> AdviceResponse;

// src/notify.rs — optional non-blocking HTTP/HTTPS webhook / ntfy alert dispatcher with cooldown.
pub fn parse_webhook_url(raw: &str) -> anyhow::Result<WebhookTarget>;
pub async fn run_loop(cfg: Alerts, rx: mpsc::Receiver<AlertMsg>, shutdown: watch::Receiver<bool>);
```
