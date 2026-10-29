#!/bin/sh
# Installs SecGram from the extracted tar.xz archive.
# Run as root for a system wide install (/opt/secgram),
# or as a normal user for ~/.local.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ "$(id -u)" = "0" ]; then
	PREFIX=/usr
	OPT=/opt/secgram
else
	PREFIX="$HOME/.local"
	OPT="$HOME/.local/opt/secgram"
fi
install -Dm755 "$HERE/SecGram" "$OPT/SecGram"
install -Dm755 "$HERE/secgram" "$PREFIX/bin/secgram"
sed -i "s|for dir in /opt/secgram|for dir in $OPT|" "$PREFIX/bin/secgram"
install -Dm644 "$HERE/secgram.desktop" \
	"$PREFIX/share/applications/secgram.desktop"
install -Dm644 "$HERE/secgram.svg" \
	"$PREFIX/share/icons/hicolor/scalable/apps/secgram.svg"
command -v update-desktop-database >/dev/null 2>&1 \
	&& update-desktop-database "$PREFIX/share/applications" || true
echo "SecGram installed. Run: secgram"
