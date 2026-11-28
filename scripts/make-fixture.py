#!/usr/bin/env python3
"""Make a redacted golden-test fixture from a linkwatch session.

Usage:
    python3 -I scripts/make-fixture.py <session_dir> <out_dir> [--from ISO] [--to ISO] [--salt TEXT]

Copies a time slice of every stream (samples, events, wifi, speed, host; plain or .gz)
and meta.json, and removes private data (see testdata/golden/README.md for the rules).
Python 3 standard library only. Review the output by eye before you commit it.

Exit code: 0 = ok, 1 = bad input, 2 = self-check found private-looking data
(the output files are deleted in that case).
"""

import argparse
import collections
import datetime as dt
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys

STREAMS = ("samples", "events", "wifi", "speed", "host")

# Public probe targets (defaults in src/config.rs and common alternatives). Kept as they are.
IP_ALLOW = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
}
FAKE_NETS = ("192.0.2", "198.51.100", "203.0.113")  # RFC 5737 documentation ranges

MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2})([:-])(?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f]|[:-][0-9A-Fa-f]{2})")
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!\d)(?!\.\d)")
# IPv6 with "::" or full 8 groups. Timestamps like 10:01:40 do not match.
IP6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}(?::[0-9A-Fa-f]{1,4}){1,6}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7})(?![0-9A-Fa-f:])"
)
SSID_TEXT_RE = re.compile(r"""(?i)\bssid\b\s*[=:]?\s*(["'])(.+?)\1""")
URL_RE = re.compile(r"""(?i)\b(https?://)([^\s"'<>/?#]*)([^\s"'<>?#]*)(\?[^\s"'<>#]*)?(#[^\s"'<>]*)?""")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

HOST_KEYS = {"host", "hostname", "host_name", "nodename", "node_name"}
HOSTID_KEYS = {"host_id", "hostid", "machine_id", "machineid", "machine-id", "product_uuid", "serial", "serial_number"}
BOOT_KEYS = {"boot_id", "prev_boot_id"}
RUN_KEYS = {"run"}
FREE_KEYS = {"label", "note", "user", "username", "email", "owner"}
POINT_KEYS = {"point"}
# meta.json config entries with these key parts are dropped.
CONFIG_DROP = re.compile(r"(?i)token|secret|passw|webhook|url|uri|path|dir|file|key|cert|credential|auth|email|user|smtp|chat_id|bot")
PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8")]


class Redactor:
    def __init__(self, salt):
        self.salt = salt.encode()
        self.counts = collections.Counter()
        self.macs = {}          # normalized original -> fake
        self.fake_macs = set()
        self.ips = {}           # original -> fake
        self.fake_ips = {}      # fake -> original
        self.nets = {}          # original /24 prefix -> fake prefix
        self.ssids = {}         # original -> ssid-N
        self.ssid_re = None
        self.ordinals = collections.defaultdict(dict)  # kind -> {orig: n}
        self.secrets_seen = set()  # original strings that must not appear in the output

    # --- collectors -------------------------------------------------------------------
    def learn(self, obj, key=None):
        """First pass: collect SSIDs (they are free text elsewhere) and hostnames."""
        if isinstance(obj, dict):
            for k, v in obj.items():
                self.learn(v, k)
        elif isinstance(obj, list):
            for v in obj:
                self.learn(v, key)
        elif isinstance(obj, str):
            lk = (key or "").lower()
            if "ssid" in lk and "bssid" not in lk and obj.strip():
                self.ssid(obj)
            elif lk in HOST_KEYS | HOSTID_KEYS | BOOT_KEYS and obj.strip():
                self.secrets_seen.add(obj)
            for m in SSID_TEXT_RE.finditer(obj):
                self.ssid(m.group(2))

    def finish_learning(self):
        names = sorted(self.ssids, key=len, reverse=True)
        self.ssid_re = re.compile("|".join(re.escape(n) for n in names)) if names else None

    # --- replacements -----------------------------------------------------------------
    def ssid(self, name):
        if name not in self.ssids:
            self.ssids[name] = "ssid-%d" % (len(self.ssids) + 1)
            self.counts["ssid"] += 1
            if len(name) >= 4:
                self.secrets_seen.add(name)
        return self.ssids[name]

    def mac(self, m):
        text = m.group(0)
        sep = m.group(2)
        norm = text.lower().replace("-", ":")
        if norm not in self.macs:
            d = hmac.new(self.salt, norm.encode(), hashlib.sha256).digest()
            octets = bytes([0x02]) + d[:5]  # locally administered, unicast
            self.macs[norm] = ":".join("%02x" % b for b in octets)
            self.counts["mac"] += 1
        fake = self.macs[norm]
        self.fake_macs.add(fake)
        out = fake.replace(":", sep)
        return out.upper() if text.isupper() else out

    def ip(self, m):
        text = m.group(1)
        octets = text.split(".")
        if any(not (0 <= int(o) <= 255) or (len(o) > 1 and o[0] == "0") for o in octets):
            return text
        if text in IP_ALLOW:
            return text
        if text in self.ips:
            return self.ips[text]
        prefix = ".".join(octets[:3])
        host = int(octets[3])
        if prefix not in self.nets and len(self.nets) < len(FAKE_NETS):
            self.nets[prefix] = FAKE_NETS[len(self.nets)]
        fake = None
        if prefix in self.nets:
            cand = "%s.%d" % (self.nets[prefix], host)
            if cand not in self.fake_ips:
                fake = cand
        if fake is None:  # more than three source subnets, or a clash: take a free address
            for net in FAKE_NETS:
                for h in range(1, 255):
                    cand = "%s.%d" % (net, h)
                    if cand not in self.fake_ips:
                        fake = cand
                        break
                if fake:
                    break
        if fake is None:
            raise SystemExit("error: more than 762 distinct addresses to replace")
        self.ips[text] = fake
        self.fake_ips[fake] = text
        self.counts["ipv4"] += 1
        return fake

    def ip6(self, m):
        text = m.group(0).lower()
        try:
            ipaddress.IPv6Address(text)
        except ValueError:
            return m.group(0)
        if text not in self.ips:
            d = hmac.new(self.salt, text.encode(), hashlib.sha256).digest()
            self.ips[text] = "2001:db8::%x:%x" % (int.from_bytes(d[:2], "big"), int.from_bytes(d[2:4], "big"))
            self.counts["ipv6"] += 1
        return self.ips[text]

    def url(self, m):
        scheme, auth, path, query, frag = m.groups()
        host = auth.rsplit("@", 1)[-1]
        if "@" in auth or query or frag:
            self.counts["url-parts"] += 1
        return scheme + host + path  # drop user info, query and fragment

    def ordinal(self, kind, value, fmt):
        d = self.ordinals[kind]
        if value not in d:
            d[value] = len(d) + 1
            self.counts[kind] += 1
        return fmt % d[value]

    # --- text and tree ----------------------------------------------------------------
    def text(self, s):
        if self.ssid_re:
            s = self.ssid_re.sub(lambda m: self.ssids[m.group(0)], s)
        s = URL_RE.sub(self.url, s)
        s = EMAIL_RE.sub(lambda m: self.count("email", "user@example.invalid"), s)
        s = MAC_RE.sub(self.mac, s)
        s = IP6_RE.sub(self.ip6, s)
        s = IP_RE.sub(self.ip, s)
        return s

    def count(self, kind, value):
        self.counts[kind] += 1
        return value

    def value(self, key, v):
        lk = (key or "").lower()
        if isinstance(v, str):
            if not v:
                return v
            if lk in HOST_KEYS:
                self.counts["hostname"] += 1
                return "host-redacted"
            if lk in HOSTID_KEYS:
                self.counts["host_id"] += 1
                return "hostid-redacted"
            if lk in BOOT_KEYS:
                return self.ordinal("boot_id", v, "boot-%d")
            if lk in RUN_KEYS:
                return self.ordinal("run", v, "run-%d")
            if lk in FREE_KEYS:
                self.counts["free-text"] += 1
                return "redacted"
            if lk in POINT_KEYS:
                return self.ordinal("point", v, "point-%d")
            if "ssid" in lk and "bssid" not in lk:
                return self.ssid(v)
        return self.walk(v, key)

    def walk(self, o, key=None):
        if isinstance(o, dict):
            return {self.text(k): self.value(k, v) for k, v in o.items()}
        if isinstance(o, list):
            return [self.value(key, v) for v in o]
        if isinstance(o, str):
            return self.text(o)
        return o


def drop_config(c):
    """Remove tokens, URLs, paths and similar from the stored config."""
    if isinstance(c, dict):
        out = {}
        for k, v in c.items():
            if CONFIG_DROP.search(str(k)):
                continue
            if isinstance(v, str) and (re.match(r"(?i)^(https?://|[a-z]:\\|/|~)", v) or "\\" in v):
                continue
            out[k] = drop_config(v)
        return out
    if isinstance(c, list):
        return [drop_config(v) for v in c
                if not (isinstance(v, str) and re.match(r"(?i)^(https?://|[a-z]:\\|/|~)", v))]
    return c


def parse_ts(s):
    s = s.strip()
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1] + "+00:00"
    s = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], s, count=1)
    d = dt.datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def stream_files(session):
    """{(stream, day): [paths]} with .jsonl.gz before .jsonl."""
    found = collections.defaultdict(list)
    for name in sorted(os.listdir(session)):
        m = re.fullmatch(r"(%s)-(\d{8})\.jsonl(\.gz)?" % "|".join(STREAMS), name)
        if m:
            found[(m.group(1), m.group(2))].append((bool(m.group(3)), os.path.join(session, name)))
    return {k: [p for _, p in sorted(v, key=lambda x: not x[0])] for k, v in found.items()}


def read_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.strip():
                yield line


def self_check(red, out_dir, written):
    problems = []
    mac_re = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f])")
    ip_re = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d])")
    for path in written:
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                where = "%s:%d" % (os.path.basename(path), n)
                for m in mac_re.finditer(line):
                    if m.group(0).lower().replace("-", ":") not in red.fake_macs:
                        problems.append("%s: MAC-like string %s" % (where, m.group(0)))
                for m in ip_re.finditer(line):
                    s = m.group(1)
                    try:
                        a = ipaddress.IPv4Address(s)
                    except ValueError:
                        continue
                    if s in IP_ALLOW or s in red.fake_ips:
                        continue
                    if any(a in n_ for n_ in PRIVATE_NETS):
                        problems.append("%s: private IPv4 %s" % (where, s))
                    else:
                        problems.append("%s: unexpected IPv4 %s" % (where, s))
                if "@" in line and EMAIL_RE.search(line.replace("user@example.invalid", "")):
                    problems.append("%s: e-mail like string" % where)
                low = line.lower()
                for secret in red.secrets_seen:
                    if secret.lower() in low:
                        problems.append("%s: original name still present (%d chars)" % (where, len(secret)))
    return problems[:50]


def main():
    ap = argparse.ArgumentParser(description="Make a redacted golden fixture from a linkwatch session.")
    ap.add_argument("session_dir")
    ap.add_argument("out_dir")
    ap.add_argument("--from", dest="t_from", help="keep records at or after this ISO time (UTC if no zone)")
    ap.add_argument("--to", dest="t_to", help="keep records before this ISO time (UTC if no zone)")
    ap.add_argument("--salt", help="salt for MAC fakes; same salt gives the same fakes on every run "
                                   "(default: random per run, keeps fakes unguessable)")
    args = ap.parse_args()
    if not os.path.isdir(args.session_dir):
        print("error: not a directory: %s" % args.session_dir, file=sys.stderr)
        return 1
    t_from = parse_ts(args.t_from) if args.t_from else None
    t_to = parse_ts(args.t_to) if args.t_to else None
    red = Redactor(args.salt if args.salt is not None else secrets.token_hex(16))

    meta = None
    meta_path = os.path.join(args.session_dir, "meta.json")
    if os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        if isinstance(meta, dict) and "config" in meta:
            meta["config"] = drop_config(meta["config"])

    files = stream_files(args.session_dir)
    if not files:
        print("error: no stream files in %s" % args.session_dir, file=sys.stderr)
        return 1

    # Pass 1: learn SSIDs and host names over the whole input.
    if meta is not None:
        red.learn(meta)
    kept = collections.defaultdict(list)  # (stream, day) -> [object]
    dropped = collections.Counter()
    for (stream, day), paths in sorted(files.items()):
        seen = set()
        for path in paths:
            for line in read_lines(path):
                try:
                    obj = json.loads(line)
                    ts = parse_ts(obj["ts"])
                except (ValueError, KeyError, TypeError):
                    dropped["malformed line"] += 1
                    continue
                if (t_from and ts < t_from) or (t_to and ts >= t_to):
                    dropped["outside time slice"] += 1
                    continue
                seq = obj.get("seq")
                if seq is not None:
                    if seq in seen:
                        dropped["duplicate seq"] += 1
                        continue
                    seen.add(seq)
                red.learn(obj)
                kept[(stream, day)].append(obj)
    red.finish_learning()

    # Pass 2: redact and write.
    os.makedirs(args.out_dir, exist_ok=True)
    written = []
    total = 0
    for (stream, day), objs in sorted(kept.items()):
        if not objs:
            continue
        path = os.path.join(args.out_dir, "%s-%s.jsonl" % (stream, day))
        with open(path, "w", encoding="utf-8") as f:
            for o in objs:
                f.write(json.dumps(red.walk(o), separators=(",", ":"), ensure_ascii=False) + "\n")
                total += 1
        written.append(path)
    if meta is not None:
        path = os.path.join(args.out_dir, "meta.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(red.walk(meta), f, indent=2, ensure_ascii=False)
            f.write("\n")
        written.append(path)
    if not total:
        print("error: no records in the selected time slice", file=sys.stderr)
        return 1

    problems = self_check(red, args.out_dir, written)
    if problems:
        for p in written:
            os.remove(p)
        print("SELF-CHECK FAILED: private-looking data remains. Output files deleted.", file=sys.stderr)
        for p in problems:
            print("  " + p, file=sys.stderr)
        return 2

    print("wrote %d records in %d file(s) to %s" % (total, len(written), args.out_dir))
    print("replaced:")
    for k in ("mac", "ipv4", "ipv6", "ssid", "hostname", "host_id", "boot_id", "run", "point",
              "free-text", "email", "url-parts"):
        if red.counts[k]:
            print("  %-10s %d distinct/occurrences" % (k, red.counts[k]))
    print("kept public targets: %s" % ", ".join(sorted(IP_ALLOW)))
    if dropped:
        print("not copied: " + ", ".join("%s=%d" % kv for kv in sorted(dropped.items())))
    print("self-check passed (no real MAC, private or unexpected IPv4, e-mail or known name left).")
    print("NOW REVIEW EVERY FILE BY EYE before you commit: the repository is public.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
