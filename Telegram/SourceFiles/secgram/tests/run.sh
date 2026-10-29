#!/usr/bin/env bash
# Standalone smoke test of the SecGram analyzer (needs only Qt6Core).
set -euo pipefail
cd "$(dirname "$0")"
SRC=../..
OUT=$(mktemp -d)
g++ -std=c++20 -O1 -fPIC -I"$SRC" $(pkg-config --cflags Qt6Core) \
  secgram_analyzer_smoke.cpp "$SRC/secgram/secgram_analyzer.cpp" \
  $(pkg-config --libs Qt6Core) -o "$OUT/smoke"
"$OUT/smoke"
