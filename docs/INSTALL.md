# Install and First Measurement

This guide is for a person who does not know the project. Do the steps in order.
The result is a monitor that records one night (or more) in one room and a report that tells
where the connection breaks: Wi-Fi, router, line, or internet.

## 1. What you need

- A Linux computer that stays in the room under test: a mini-PC, a Raspberry Pi (64-bit OS),
  or a laptop on mains power. Debian, Ubuntu, and Raspberry Pi OS are tested.
- Wi-Fi on that computer, connected to the network under test.
- Optional but strongly recommended: an Ethernet cable from the same computer to a router LAN
  port. With two paths, `linkwatch` can tell a Wi-Fi fault from a router or ISP fault.
  Without the cable, a support pack for the ISP gets low readiness.
- About 1 GB of free disk space per week of measurement.

## 2. Get the package

Each release on GitHub has ready files for `amd64` and `arm64` (Raspberry Pi 4/5 with a
64-bit OS):

1. Open the releases page of the repository and select the newest release.
2. Download `linkwatch_<version>_<arch>.deb` and `SHA256SUMS.txt`.
3. Check the file: `sha256sum -c --ignore-missing SHA256SUMS.txt`

To build the package yourself (other CPU types, or local changes):

1. Install Rust: `curl https://sh.rustup.rs -sSf | sh` (accept the defaults).
2. Get the source code and go into its folder.
3. Build: `cargo build --release --locked`
4. Make the package: `packaging/build-deb.sh target/release/linkwatch`
5. The package is in `target/deb/linkwatch_<version>_<arch>.deb`.

## 3. Install

```sh
sudo dpkg -i linkwatch_<version>_<arch>.deb
```

The package:
- creates the system user `linkwatch`,
- installs `/etc/linkwatch/linkwatch.toml` (it never overwrites your copy),
- installs `/etc/sysctl.d/90-linkwatch.conf` and applies it (see "Kernel settings" below),
- enables `linkwatch.service`, but does **not** start it on the first install.

### Kernel settings

The file `/etc/sysctl.d/90-linkwatch.conf` sets these values:
- `net.ipv4.ping_group_range = 0 2147483647`. This lets the service send ICMP echo without
  root rights. `linkwatch check` reports `icmp permission` FAIL if this value is missing.
- `net.ipv4.conf.all.arp_ignore = 1` and `net.ipv4.conf.all.arp_announce = 2`. The kernel
  answers ARP only on the interface that owns the address.
- `net.ipv4.conf.all.rp_filter = 2` and `net.ipv4.conf.default.rp_filter = 2`. The kernel
  uses the loose reverse-path filter.

The ARP and `rp_filter` values apply to all interfaces of the host. The monitor needs them
only when Wi-Fi and Ethernet sit in the same subnet. On a typical home host they are safe.
Many distributions use `rp_filter = 2` already. A host with one interface sees no change.
A host that acts as a router or firewall can see a change. Check it before you install.

To remove these settings:
1. Run `sudo rm /etc/sysctl.d/90-linkwatch.conf`.
2. Reboot the host, or set the old values by hand with `sysctl -w`.
3. If you remove the `ping_group_range` line, the service cannot ping. Set it in another file.

Removing the package does not reset the running values. They stay until the next reboot.

### TLS and webhook tokens

Warning: linkwatch uses `rustls-rustcrypto`. This crypto provider is a pre-release and has no
audit. It protects two things: the CVE lookup and the `[alerts]` webhooks. A webhook bearer
token travels over this TLS stack. Use a token that you can revoke. Do not reuse it elsewhere.

## 4. Configure

Open the configuration: `sudo nano /etc/linkwatch/linkwatch.toml`

1. Name the interfaces (find the names with `ip link`). Without `[[interfaces]]`, all physical
   interfaces are monitored.
   ```toml
   [[interfaces]]
   name = "wlo1"
   role = "wifi"
   [[interfaces]]
   name = "enp1s0"
   role = "ethernet"
   ```
2. Name the place of this measurement. Use one point name per room:
   ```toml
   [site]
   point = "B1/F6/R2"      # building / flat / room
   label = "room 2"
   ```
3. To open the web UI from a phone or another computer, set a listen address and a token
   (16 or more characters of `A-Z a-z 0-9 _ -`):
   ```toml
   [web]
   listen = "0.0.0.0:8080"
   token = "put-a-long-random-string-here"
   ```
4. Save the file.

## 5. Check before the run

```sh
sudo -u linkwatch linkwatch --config /etc/linkwatch/linkwatch.toml check
```

Each line starts with `ok`, `WARN`, or `FAIL`. Every `WARN` and `FAIL` line has a `fix:` line
below it.

- Correct every `FAIL` line, then run the check again.
- Read every `WARN` line. Most of them are settings of the computer that can look like a
  network fault: Wi-Fi power-save, USB autosuspend, a VPN, a bad cable, two network
  managers, Bluetooth on 2.4 GHz. Correct them if you can.
- `wifi scan ... needs CAP_NET_ADMIN` is normal for this manual check. The service has the
  permission.

Optional, before a long run:
- `... check --deep` adds about 6 s of active self-tests: timer delay, loopback RTT, CPU and
  disk pressure, and a proof that replies arrive on the interface that sent the probe.
- `... calibrate --seconds 60` measures the idle noise of every path and writes
  `/var/lib/linkwatch/calibration.json`. Keep the device and the network idle while it runs.
  The file is informational. `analyze` and `compare` do not read it yet.

## 6. Start the measurement

```sh
sudo systemctl start linkwatch
systemctl status linkwatch          # must show "active (running)"
journalctl -u linkwatch -n 20       # shows the session name, e.g. 20261128T003520Z_B1_F6_R2
```

Let it run for at least one full night (6 hours or more). Do not use the computer for large
downloads during the run. If you do, the report marks that time as the observer's own traffic.

Open the web UI: `http://<computer-address>:8080/?token=<token>` (one time with the token;
the browser keeps it).

## 7. Read the result

```sh
linkwatch --config /etc/linkwatch/linkwatch.toml sessions               # list sessions
linkwatch --config /etc/linkwatch/linkwatch.toml analyze <session> > report.md
```

In the report, look first at:
- **Observer trust.** `clean`: the result is about the network. `caution`: short host
  effects, already excluded. `polluted`: the computer itself distorted the measurement.
  Correct the reasons and measure again.
- **Incidents and their cause** (Wi-Fi, router, line, internet, DNS).

A short report for the ISP or the landlord (with private data removed):

```sh
linkwatch --config /etc/linkwatch/linkwatch.toml support-report <session> --audience isp --lang uk --format md > ticket.md
```

## 8. Measure in another room

1. Stop the service: `sudo systemctl stop linkwatch`
2. Move the computer.
3. Change `point` and `label` in `/etc/linkwatch/linkwatch.toml`.
4. Run the check (step 5), then start the service (step 6).
5. Compare rooms: `linkwatch compare <session-1> <session-2> > compare.md`

## 9. Update and remove

- Update: install the new package with `sudo dpkg -i`. A running service restarts and
  continues the same session.
- Remove the program, keep the data: `sudo dpkg -r linkwatch`
- Remove everything, including `/etc/linkwatch`: `sudo dpkg -P linkwatch`.
  The data in `/var/lib/linkwatch` stays. Delete it yourself if you do not need it.

## 10. Problems

| Symptom | What to do |
|---|---|
| `icmp permission` FAIL | `sudo sysctl -p /etc/sysctl.d/90-linkwatch.conf` |
| `data dir` FAIL | Run the check as the `linkwatch` user (`sudo -u linkwatch ...`), not as yourself |
| Service is not `active` | `journalctl -u linkwatch -n 50` shows the error |
| Web UI does not open from the phone | Set `listen = "0.0.0.0:8080"` and `token`, then `sudo systemctl restart linkwatch` |
| `cannot read config ... Permission denied` | Use `sudo`: the configuration holds the token and only root and the `linkwatch` group can read it |
