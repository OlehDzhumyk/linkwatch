//! Minimal generic-netlink client: socket, message builder and TLV parser.
//!
//! The parser works on untrusted kernel bytes. Every length is checked; a
//! truncated or malformed buffer gives an error, never a panic. Netlink
//! attributes are 4-byte aligned; the last attribute may omit its padding.

use anyhow::{Context, Result, anyhow, bail};
use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

// <linux/netlink.h>
pub const NLMSG_HDRLEN: usize = 16;
pub const NLMSG_NOOP: u16 = 1;
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_MULTI: u16 = 0x2;
pub const NLM_F_ACK: u16 = 0x4;
/// NLM_F_ROOT | NLM_F_MATCH.
pub const NLM_F_DUMP: u16 = 0x300;
const NLA_HDRLEN: usize = 4;
/// Mask that removes NLA_F_NESTED (0x8000) and NLA_F_NET_BYTEORDER (0x4000).
const NLA_TYPE_MASK: u16 = 0x3fff;

// <linux/genetlink.h>
pub const GENL_HDRLEN: usize = 4;
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
pub const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
pub const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;

const RECV_BUF: usize = 64 * 1024;
/// Upper bound on messages per request, so a broken kernel stream cannot loop forever.
const MAX_MSGS: usize = 100_000;

/// Rounds up to the 4-byte netlink alignment.
pub const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One netlink attribute (type without flag bits, payload without header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn u8(&self) -> Option<u8> {
        self.data.first().copied()
    }
    pub fn i8(&self) -> Option<i8> {
        self.u8().map(|v| v as i8)
    }
    pub fn u16(&self) -> Option<u16> {
        Some(u16::from_ne_bytes(self.data.get(..2)?.try_into().ok()?))
    }
    pub fn u32(&self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.data.get(..4)?.try_into().ok()?))
    }
    pub fn i32(&self) -> Option<i32> {
        self.u32().map(|v| v as i32)
    }
    /// u64, or a u32 widened (some kernels send 32-bit counters).
    pub fn u64(&self) -> Option<u64> {
        match self.data.len() {
            8.. => Some(u64::from_ne_bytes(self.data.get(..8)?.try_into().ok()?)),
            4..=7 => self.u32().map(u64::from),
            _ => None,
        }
    }
    /// String without trailing NUL bytes, lossy UTF-8.
    pub fn string(&self) -> String {
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        String::from_utf8_lossy(&self.data[..end]).into_owned()
    }
    pub fn nested(&self) -> Result<Vec<Attr<'a>>> {
        parse_attrs(self.data)
    }
}

/// Parses a sequence of attributes.
pub fn parse_attrs(buf: &[u8]) -> Result<Vec<Attr<'_>>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < NLA_HDRLEN {
            bail!(
                "netlink attribute header truncated ({} bytes left)",
                rest.len()
            );
        }
        let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
        let kind = u16::from_ne_bytes([rest[2], rest[3]]) & NLA_TYPE_MASK;
        if len < NLA_HDRLEN || len > rest.len() {
            bail!(
                "netlink attribute {kind} has bad length {len} ({} bytes left)",
                rest.len()
            );
        }
        out.push(Attr {
            kind,
            data: &rest[NLA_HDRLEN..len],
        });
        off = off.saturating_add(align4(len)).min(buf.len());
    }
    Ok(out)
}

/// First attribute of `kind`.
pub fn find<'a>(attrs: &[Attr<'a>], kind: u16) -> Option<Attr<'a>> {
    attrs.iter().find(|a| a.kind == kind).copied()
}

/// One netlink message; `payload` excludes the 16-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg<'a> {
    pub ty: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// Splits a datagram into netlink messages.
pub fn parse_messages(buf: &[u8]) -> Result<Vec<Msg<'_>>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        let rest = &buf[off..];
        if rest.len() < NLMSG_HDRLEN {
            bail!(
                "netlink message header truncated ({} bytes left)",
                rest.len()
            );
        }
        let len = u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        if len < NLMSG_HDRLEN || len > rest.len() {
            bail!(
                "netlink message has bad length {len} ({} bytes left)",
                rest.len()
            );
        }
        out.push(Msg {
            ty: u16::from_ne_bytes([rest[4], rest[5]]),
            flags: u16::from_ne_bytes([rest[6], rest[7]]),
            seq: u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]),
            payload: &rest[NLMSG_HDRLEN..len],
        });
        off = off.saturating_add(align4(len)).min(buf.len());
    }
    Ok(out)
}

/// Payload of an NLMSG_ERROR message: 0 = ACK, otherwise a negative errno.
pub fn error_code(payload: &[u8]) -> Result<i32> {
    let b = payload
        .get(..4)
        .ok_or_else(|| anyhow!("NLMSG_ERROR payload truncated"))?;
    Ok(i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

/// Builds one generic-netlink request.
pub struct MsgBuilder {
    buf: Vec<u8>,
}

impl MsgBuilder {
    pub fn new(family: u16, flags: u16, seq: u32, cmd: u8, version: u8) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set in finish()
        buf.extend_from_slice(&family.to_ne_bytes());
        buf.extend_from_slice(&flags.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: kernel fills in
        buf.extend_from_slice(&[cmd, version, 0, 0]);
        Self { buf }
    }

    pub fn attr(mut self, kind: u16, data: &[u8]) -> Self {
        let len = NLA_HDRLEN + data.len();
        // Attribute payloads here are tiny (ids, names); u16 cannot overflow.
        let len16 = u16::try_from(len).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len16.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align4(self.buf.len()), 0);
        self
    }

    pub fn attr_u32(self, kind: u16, v: u32) -> Self {
        self.attr(kind, &v.to_ne_bytes())
    }

    /// NUL-terminated string attribute.
    pub fn attr_str(self, kind: u16, s: &str) -> Self {
        let mut d = s.as_bytes().to_vec();
        d.push(0);
        self.attr(kind, &d)
    }

    pub fn finish(mut self) -> Vec<u8> {
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

/// Blocking NETLINK_GENERIC socket with send and receive timeouts.
#[derive(Debug)]
pub struct GenlSocket {
    sock: netlink_sys::Socket,
    seq: u32,
    buf: Vec<u8>,
}

impl GenlSocket {
    pub fn open(timeout: Duration) -> Result<Self> {
        let sock = open_socket_with_timeout(None, timeout, true)?;
        Ok(Self {
            sock,
            seq: 1,
            buf: vec![0u8; RECV_BUF],
        })
    }

    /// Opens a generic netlink socket subscribed to multicast group `group_id` (supports any group ID via NETLINK_ADD_MEMBERSHIP).
    pub fn open_multicast(group_id: u32, timeout: Duration) -> Result<Self> {
        let sock = open_socket_with_timeout(Some(group_id), timeout, false)?;
        Ok(Self {
            sock,
            seq: 1,
            buf: vec![0u8; RECV_BUF],
        })
    }

    pub fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1).max(1);
        self.seq
    }

    /// Receives one netlink datagram, returning `Ok(None)` on receive timeout or ENOBUFS.
    pub fn recv_datagram(&mut self) -> Result<Option<Vec<u8>>> {
        use nix::sys::socket::{MsgFlags, recv};
        loop {
            match recv(self.sock.as_raw_fd(), &mut self.buf, MsgFlags::MSG_TRUNC) {
                Ok(n) => {
                    if n > self.buf.len() {
                        bail!("netlink datagram truncated ({n} > {} bytes)", self.buf.len());
                    }
                    return Ok(Some(self.buf[..n].to_vec()));
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EAGAIN) => return Ok(None),
                Err(nix::errno::Errno::ENOBUFS) => {
                    tracing::warn!("netlink multicast buffer overrun (ENOBUFS), continuing");
                    return Ok(None);
                }
                Err(e) => return Err(io::Error::from(e)).context("netlink recv failed"),
            }
        }
    }

    /// Sends `req` (built with sequence `seq`) and collects the payloads of
    /// all reply messages until ACK or NLMSG_DONE. Kernel errors are returned
    /// as `io::Error` inside the anyhow chain (downcast to inspect errno).
    pub fn request(&mut self, req: &[u8], seq: u32) -> Result<Vec<Vec<u8>>> {
        use nix::sys::socket::{MsgFlags, recv, send};
        send(self.sock.as_raw_fd(), req, MsgFlags::empty())
            .map_err(io::Error::from)
            .context("netlink send failed")?;
        let dump = req
            .get(6..8)
            .is_some_and(|f| u16::from_ne_bytes([f[0], f[1]]) & NLM_F_DUMP != 0);
        let mut out = Vec::new();
        let mut seen = 0usize;
        loop {
            // MSG_TRUNC makes recv return the real datagram size.
            let n = match recv(self.sock.as_raw_fd(), &mut self.buf, MsgFlags::MSG_TRUNC) {
                Ok(n) => n,
                Err(nix::errno::Errno::EINTR) => continue,
                Err(nix::errno::Errno::EAGAIN) => bail!("netlink reply timed out"),
                Err(e) => return Err(io::Error::from(e)).context("netlink recv failed"),
            };
            if n > self.buf.len() {
                bail!("netlink reply truncated ({n} > {} bytes)", self.buf.len());
            }
            for m in parse_messages(&self.buf[..n])? {
                seen += 1;
                if seen > MAX_MSGS {
                    bail!("netlink reply has too many messages");
                }
                if m.seq != seq {
                    continue; // stale reply of an earlier, timed-out request
                }
                match m.ty {
                    NLMSG_NOOP => {}
                    NLMSG_ERROR => {
                        let code = error_code(m.payload)?;
                        if code == 0 {
                            return Ok(out);
                        }
                        return Err(io::Error::from_raw_os_error(code.saturating_neg()).into());
                    }
                    NLMSG_DONE => return Ok(out),
                    _ => {
                        out.push(m.payload.to_vec());
                        if !dump && m.flags & NLM_F_MULTI == 0 && req_wants_no_ack(req) {
                            return Ok(out);
                        }
                    }
                }
            }
        }
    }

    /// Resolves a generic-netlink family name to its id and multicast groups.
    pub fn family_info(&mut self, name: &str) -> Result<(u16, Vec<(String, u32)>)> {
        let seq = self.next_seq();
        let req = MsgBuilder::new(
            GENL_ID_CTRL,
            NLM_F_REQUEST | NLM_F_ACK,
            seq,
            CTRL_CMD_GETFAMILY,
            1,
        )
        .attr_str(CTRL_ATTR_FAMILY_NAME, name)
        .finish();
        let replies = self
            .request(&req, seq)
            .with_context(|| format!("generic netlink family {name:?} not found"))?;
        let mut id = None;
        let mut groups = Vec::new();
        for p in &replies {
            let attrs = parse_attrs(p.get(GENL_HDRLEN..).unwrap_or_default())?;
            if let Some(fid) = find(&attrs, CTRL_ATTR_FAMILY_ID).and_then(|a| a.u16()) {
                id = Some(fid);
            }
            if let Some(mg) = find(&attrs, CTRL_ATTR_MCAST_GROUPS) {
                groups.extend(parse_mcast_groups(mg.data)?);
            }
        }
        let id = id.ok_or_else(|| anyhow!("generic netlink family {name:?}: no id in reply"))?;
        Ok((id, groups))
    }

    /// Resolves a generic-netlink family name to its id.
    pub fn family_id(&mut self, name: &str) -> Result<u16> {
        self.family_info(name).map(|(id, _)| id)
    }
}

fn open_socket_with_timeout(
    group_id: Option<u32>,
    timeout: Duration,
    set_send_timeout: bool,
) -> Result<netlink_sys::Socket> {
    use nix::sys::socket::{setsockopt, sockopt};
    let mut sock = netlink_sys::Socket::new(netlink_sys::protocols::NETLINK_GENERIC)
        .context("cannot open netlink socket")?;
    sock.bind_auto().context("cannot bind netlink socket")?;
    if let Some(id) = group_id {
        sock.add_membership(id)
            .with_context(|| format!("cannot subscribe to netlink multicast group {id}"))?;
    }
    let tv = nix::sys::time::TimeVal::new(
        timeout.as_secs().try_into().unwrap_or(i32::MAX.into()),
        timeout.subsec_micros().into(),
    );
    setsockopt(&sock, sockopt::ReceiveTimeout, &tv)
        .map_err(io::Error::from)
        .context("cannot set netlink timeout")?;
    if set_send_timeout {
        setsockopt(&sock, sockopt::SendTimeout, &tv)
            .map_err(io::Error::from)
            .context("cannot set netlink timeout")?;
    }
    Ok(sock)
}

/// Parses `CTRL_ATTR_MCAST_GROUPS` nested list into `(name, group_id)`.
pub fn parse_mcast_groups(attrs_buf: &[u8]) -> Result<Vec<(String, u32)>> {
    let mut out = Vec::new();
    for item in parse_attrs(attrs_buf)? {
        let nested = item.nested()?;
        if let (Some(name), Some(id)) = (
            find(&nested, CTRL_ATTR_MCAST_GRP_NAME).map(|a| a.string()),
            find(&nested, CTRL_ATTR_MCAST_GRP_ID).and_then(|a| a.u32()),
        ) && !name.is_empty()
        {
            out.push((name, id));
        }
    }
    Ok(out)
}

fn req_wants_no_ack(req: &[u8]) -> bool {
    req.get(6..8)
        .is_some_and(|f| u16::from_ne_bytes([f[0], f[1]]) & NLM_F_ACK == 0)
}

/// Errno of a kernel error returned by [`GenlSocket::request`], if any.
pub fn errno(e: &anyhow::Error) -> Option<i32> {
    e.chain()
        .find_map(|c| c.downcast_ref::<io::Error>())
        .and_then(|io| io.raw_os_error())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encodes one attribute with padding (test helper, also used by wifi tests).
    pub fn nla(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(data);
        v.resize(align4(v.len()), 0);
        v
    }

    pub fn nlmsg(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&flags.to_ne_bytes());
        v.extend_from_slice(&seq.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(payload);
        v.resize(align4(v.len()), 0);
        v
    }

    #[test]
    fn attrs_roundtrip_and_nesting() {
        let inner = [nla(1, &7u32.to_ne_bytes()), nla(2, &[0xd6])].concat();
        // Nested flag 0x8000 must be masked off.
        let mut buf = nla(0x8000 | 5, &inner);
        buf.extend(nla(3, b"wlo1\0"));
        let a = parse_attrs(&buf).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].kind, 5);
        let n = a[0].nested().unwrap();
        assert_eq!(find(&n, 1).unwrap().u32(), Some(7));
        assert_eq!(find(&n, 2).unwrap().i8(), Some(-42));
        assert_eq!(a[1].string(), "wlo1");
        assert_eq!(find(&a, 9), None);
    }

    #[test]
    fn last_attr_without_padding() {
        let mut buf = nla(1, &[1, 2, 3, 4]);
        buf.extend_from_slice(&5u16.to_ne_bytes());
        buf.extend_from_slice(&2u16.to_ne_bytes());
        buf.push(9); // 5-byte attribute, no padding
        let a = parse_attrs(&buf).unwrap();
        assert_eq!(a[1].data, &[9]);
    }

    #[test]
    fn malformed_attrs_are_errors() {
        let good = nla(1, &[1, 2, 3, 4]);
        assert!(parse_attrs(&good[..6]).is_err(), "length beyond buffer");
        assert!(parse_attrs(&good[..2]).is_err(), "header truncated");
        assert!(parse_attrs(&[2, 0, 1, 0]).is_err(), "length < header");
        let mut trailing = good.clone();
        trailing.extend_from_slice(&[1, 2]);
        assert!(parse_attrs(&trailing).is_err(), "trailing garbage");
        assert!(parse_attrs(&[]).unwrap().is_empty());
        // Bad nested content is caught when descending.
        let outer = nla(1, &[9, 0, 1, 0]);
        let a = parse_attrs(&outer).unwrap();
        assert!(a[0].nested().is_err());
    }

    #[test]
    fn typed_getters_check_length() {
        let a = Attr {
            kind: 1,
            data: &[1, 2],
        };
        assert_eq!(a.u32(), None);
        assert!(a.u16().is_some());
        assert_eq!(a.u64(), None);
        let b = Attr {
            kind: 1,
            data: &5u32.to_ne_bytes(),
        };
        assert_eq!(b.u64(), Some(5));
        let e = Attr { kind: 1, data: &[] };
        assert_eq!(e.u8(), None);
        assert_eq!(e.string(), "");
    }

    #[test]
    fn messages_parse_and_validate() {
        let m1 = nlmsg(30, NLM_F_MULTI, 7, &[1, 2, 3, 4, 5]);
        let m2 = nlmsg(NLMSG_DONE, NLM_F_MULTI, 7, &0i32.to_ne_bytes());
        let buf = [m1.clone(), m2].concat();
        let ms = parse_messages(&buf).unwrap();
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].payload, &[1, 2, 3, 4, 5]);
        assert_eq!(ms[0].seq, 7);
        assert_eq!(ms[1].ty, NLMSG_DONE);
        assert!(parse_messages(&m1[..10]).is_err());
        assert!(parse_messages(&m1[..18]).is_err());
        let mut bad = m1.clone();
        bad[..4].copy_from_slice(&4u32.to_ne_bytes());
        assert!(parse_messages(&bad).is_err());
    }

    #[test]
    fn error_payload() {
        assert_eq!(error_code(&(-1i32).to_ne_bytes()).unwrap(), -1);
        assert!(error_code(&[0, 0]).is_err());
    }

    #[test]
    fn builder_layout() {
        let m = MsgBuilder::new(0x1c, NLM_F_REQUEST | NLM_F_DUMP, 9, 17, 0)
            .attr_u32(3, 4)
            .finish();
        assert_eq!(m.len(), 16 + 4 + 8);
        let ms = parse_messages(&m).unwrap();
        assert_eq!(ms[0].ty, 0x1c);
        assert_eq!(ms[0].flags, NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(ms[0].payload[0], 17);
        let a = parse_attrs(&ms[0].payload[GENL_HDRLEN..]).unwrap();
        assert_eq!(a[0].u32(), Some(4));
        let s = MsgBuilder::new(1, 0, 1, 3, 1)
            .attr_str(2, "nl80211")
            .finish();
        assert_eq!(s.len() % 4, 0);
    }

    #[test]
    fn mcast_groups_parse() {
        let g1 = [nla(CTRL_ATTR_MCAST_GRP_NAME, b"config\0"), nla(CTRL_ATTR_MCAST_GRP_ID, &22u32.to_ne_bytes())].concat();
        let g2 = [nla(CTRL_ATTR_MCAST_GRP_NAME, b"mlme\0"), nla(CTRL_ATTR_MCAST_GRP_ID, &25u32.to_ne_bytes())].concat();
        let buf = [nla(0x8000 | 1, &g1), nla(0x8000 | 2, &g2)].concat();
        assert_eq!(
            parse_mcast_groups(&buf).unwrap(),
            vec![("config".into(), 22), ("mlme".into(), 25)]
        );
        assert!(parse_mcast_groups(&[5, 0, 1, 0]).is_err());
    }
}
