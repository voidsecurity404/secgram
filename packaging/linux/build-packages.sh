#!/bin/bash
# Builds SecGram release packages from a compiled Telegram binary.
#   build-packages.sh <path/to/Telegram> <version> <output dir>
# Produces: .tar.xz (any distro), .deb (Debian/Ubuntu), .rpm (RHEL/Fedora).
set -euo pipefail
BIN="$1"
VERSION="$2"
OUT="$(mkdir -p "$3" && cd "$3" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Portable archive.
mkdir -p "$WORK/SecGram"
install -m755 "$BIN" "$WORK/SecGram/SecGram"
install -m755 "$HERE/secgram" "$HERE/install.sh" "$WORK/SecGram/"
install -m644 "$HERE/secgram.desktop" "$HERE/secgram.svg" "$WORK/SecGram/"
tar -C "$WORK" -cJf "$OUT/SecGram-$VERSION-linux-x86_64.tar.xz" SecGram

# File tree shared by deb and rpm.
ROOT="$WORK/root"
install -Dm755 "$BIN" "$ROOT/opt/secgram/SecGram"
install -Dm755 "$HERE/secgram" "$ROOT/usr/bin/secgram"
install -Dm644 "$HERE/secgram.desktop" \
	"$ROOT/usr/share/applications/secgram.desktop"
install -Dm644 "$HERE/secgram.svg" \
	"$ROOT/usr/share/icons/hicolor/scalable/apps/secgram.svg"

# Debian / Ubuntu.
DEB="$WORK/deb"
cp -a "$ROOT" "$DEB"
mkdir -p "$DEB/DEBIAN"
cat > "$DEB/DEBIAN/control" <<CONTROL
Package: secgram
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.28), libglib2.0-0 | libglib2.0-0t64, libfontconfig1, libfreetype6, libx11-6, libxcb1, libgl1
Maintainer: SecGram <noreply@github.com>
Homepage: https://github.com/__OWNER__/secgram
Description: Telegram Desktop with security tools
 Link guard, file guard, scam detector, IOC extraction, evidence export,
 anti-delete and privacy features for security teams and regular users.
CONTROL
dpkg-deb --root-owner-group --build "$DEB" "$OUT/secgram_${VERSION}_amd64.deb"

# RHEL / Fedora / Rocky / Alma.
RPM="$WORK/rpm"
mkdir -p "$RPM"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
cat > "$RPM/SPECS/secgram.spec" <<SPEC
Name: secgram
Version: $VERSION
Release: 1
Summary: Telegram Desktop with security tools
License: GPLv3
URL: https://github.com/__OWNER__/secgram
Requires: glib2 fontconfig freetype libX11 libxcb mesa-libGL
AutoReqProv: no
%description
Link guard, file guard, scam detector, IOC extraction, evidence export,
anti-delete and privacy features for security teams and regular users.
%install
cp -a $ROOT/. %{buildroot}/
%files
/opt/secgram/SecGram
/usr/bin/secgram
/usr/share/applications/secgram.desktop
/usr/share/icons/hicolor/scalable/apps/secgram.svg
SPEC
rpmbuild --define "_topdir $RPM" -bb "$RPM/SPECS/secgram.spec"
cp "$RPM"/RPMS/*/*.rpm "$OUT/"
ls -la "$OUT"

# Checksums: the in-app updater refuses files that do not match.
(cd "$OUT" && sha256sum -- *.tar.xz *.deb *.rpm > SHA256SUMS.txt)
