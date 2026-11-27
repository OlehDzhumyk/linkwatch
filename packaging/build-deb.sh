#!/bin/sh
# Build a .deb from a compiled binary. Needs only dpkg-deb (Debian/Ubuntu/Raspberry Pi OS).
#   packaging/build-deb.sh target/release/linkwatch [arch] [outdir]
# arch defaults to the host's dpkg architecture (amd64, arm64, armhf).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
bin=${1:?path to linkwatch binary}
arch=${2:-$(dpkg --print-architecture)}
out=${3:-$root/target/deb}
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

install -D -m 0755 "$bin" "$stage/usr/bin/linkwatch"
sed 's#/usr/local/bin/linkwatch#/usr/bin/linkwatch#' "$root/deploy/linkwatch.service" > "$stage/linkwatch.service"
install -D -m 0644 "$stage/linkwatch.service" "$stage/usr/lib/systemd/system/linkwatch.service"
rm "$stage/linkwatch.service"
install -D -m 0644 "$root/deploy/90-linkwatch.conf" "$stage/etc/sysctl.d/90-linkwatch.conf"
install -D -m 0640 "$root/packaging/linkwatch.toml" "$stage/etc/linkwatch/linkwatch.toml"
install -D -m 0644 "$root/README.md" "$stage/usr/share/doc/linkwatch/README.md"
install -D -m 0644 "$root/LICENSE.md" "$stage/usr/share/doc/linkwatch/LICENSE.md"
install -D -m 0644 "$root/docs/FEATURES.md" "$stage/usr/share/doc/linkwatch/FEATURES.md"
install -D -m 0644 "$root/examples/linkwatch.toml" "$stage/usr/share/doc/linkwatch/examples/linkwatch.toml"
install -D -m 0644 "$root/examples/site.toml" "$stage/usr/share/doc/linkwatch/examples/site.toml"

mkdir -p "$stage/DEBIAN"
for f in postinst prerm postrm; do install -m 0755 "$root/packaging/deb/$f" "$stage/DEBIAN/$f"; done
printf '/etc/linkwatch/linkwatch.toml\n/etc/sysctl.d/90-linkwatch.conf\n' > "$stage/DEBIAN/conffiles"
size=$(du -sk "$stage" | cut -f1)
cat > "$stage/DEBIAN/control" <<CTL
Package: linkwatch
Version: $version
Architecture: $arch
Maintainer: OlehDzhumyk <93152974+OlehDzhumyk@users.noreply.github.com>
Installed-Size: $size
Depends: adduser | passwd
Section: net
Priority: optional
Homepage: https://github.com/OlehDzhumyk/linkwatch
Description: per-second network path monitor
 Finds out whether connection drops come from Wi-Fi, the router, the line
 or the internet. Probes each interface every second, records JSON Lines,
 serves a web UI and writes incident reports. PolyForm Shield 1.0.0 license.
CTL
mkdir -p "$out"
dpkg-deb --root-owner-group --build "$stage" "$out/linkwatch_${version}_${arch}.deb" >/dev/null
echo "$out/linkwatch_${version}_${arch}.deb"
