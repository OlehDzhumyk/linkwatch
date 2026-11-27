#!/bin/sh
# Install linkwatch as a systemd service. Run as root: sudo ./install.sh [path/to/linkwatch]
# What it does (nothing else):
#   1. copies the binary to /usr/local/bin/linkwatch
#   2. creates system user "linkwatch" (no login, no home)
#   3. installs /etc/linkwatch/linkwatch.toml if missing (never overwrites)
#   4. installs /etc/sysctl.d/90-linkwatch.conf and applies it
#   5. installs and enables linkwatch.service (does not start it; start with: systemctl start linkwatch)
# Undo: sudo ./install.sh --uninstall   (keeps /var/lib/linkwatch data)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
if [ "$(id -u)" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi

if [ "${1:-}" = "--uninstall" ]; then
  systemctl disable --now linkwatch.service 2>/dev/null || true
  rm -f /etc/systemd/system/linkwatch.service /usr/local/bin/linkwatch /etc/sysctl.d/90-linkwatch.conf
  systemctl daemon-reload
  sysctl --system >/dev/null
  echo "removed; config in /etc/linkwatch and data in /var/lib/linkwatch kept"
  exit 0
fi

bin=${1:-$here/linkwatch}
[ -x "$bin" ] || { echo "binary not found: $bin"; exit 1; }
install -m 0755 "$bin" /usr/local/bin/linkwatch
id linkwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin linkwatch
install -d -m 0755 /etc/linkwatch
[ -f /etc/linkwatch/linkwatch.toml ] || install -m 0640 -g linkwatch "$here/linkwatch.toml" /etc/linkwatch/linkwatch.toml
chgrp linkwatch /etc/linkwatch/linkwatch.toml && chmod 0640 /etc/linkwatch/linkwatch.toml
[ -f "$here/site.toml" ] && [ ! -f /etc/linkwatch/site.toml ] && install -m 0644 "$here/site.toml" /etc/linkwatch/site.toml
install -m 0644 "$here/90-linkwatch.conf" /etc/sysctl.d/90-linkwatch.conf
sysctl -p /etc/sysctl.d/90-linkwatch.conf >/dev/null
install -m 0644 "$here/linkwatch.service" /etc/systemd/system/linkwatch.service
systemctl daemon-reload
systemctl enable linkwatch.service
echo "installed. Edit /etc/linkwatch/linkwatch.toml, then: sudo systemctl start linkwatch"
echo "check first: sudo -u linkwatch /usr/local/bin/linkwatch --config /etc/linkwatch/linkwatch.toml check"
