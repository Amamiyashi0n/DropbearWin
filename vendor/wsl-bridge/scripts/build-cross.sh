#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET="x86_64-pc-windows-gnu"
OUT_DIR="$REPO_ROOT/dist"
DEPLOY=0
DEPLOY_DIR="/mnt/c/Users/Amamiya/Tools/wsl-bridge"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deploy) DEPLOY=1 ;;
    --deploy-dir) shift; DEPLOY_DIR="$1" ;;
    --out-dir) shift; OUT_DIR="$1" ;;
    -h|--help)
      echo "Usage: $0 [--deploy] [--deploy-dir <linux-path>] [--out-dir <linux-path>]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

export PATH="$HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
# Build on Linux VolFs for fast incremental builds and zero DrvFs lock contention
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/.cache/wsl-bridge-target}"
export RUSTFLAGS="${RUSTFLAGS:--C target-cpu=native -C link-arg=-static-libgcc}"

command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found in WSL PATH" >&2; exit 1; }
command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || { echo "error: x86_64-w64-mingw32-gcc not found" >&2; exit 1; }

echo "=== Cross-compiling wsl-bridge for $TARGET in Debian WSL1 ==="
echo "  rustc: $(rustc --version)"
echo "  gcc  : $(x86_64-w64-mingw32-gcc --version | head -n 1)"
echo "  target dir: $CARGO_TARGET_DIR"

cd "$REPO_ROOT"
cargo build --release --target "$TARGET"

BIN="$CARGO_TARGET_DIR/$TARGET/release/wsl-bridge.exe"
mkdir -p "$OUT_DIR"
cp -f "$BIN" "$OUT_DIR/wsl-bridge.exe"

echo "=== Verifying PE architecture & DLL imports ==="
file "$OUT_DIR/wsl-bridge.exe"
IMPORTS="$(x86_64-w64-mingw32-objdump -p "$OUT_DIR/wsl-bridge.exe" | grep 'DLL Name:' | awk '{print $3}' | sort -u)"
echo "$IMPORTS" | sed 's/^/  DLL: /'

if echo "$IMPORTS" | grep -iE 'libgcc|libwinpthread|libstdc\+\+|msys|cygwin' >/dev/null; then
  echo "ERROR: unexpected non-system runtime DLL dependency detected!" >&2
  exit 1
fi
echo "PE import check OK (system Windows DLLs only, size=$(stat -c%s "$OUT_DIR/wsl-bridge.exe") bytes)"

if [ "$DEPLOY" -eq 1 ]; then
  echo "=== Deploying to $DEPLOY_DIR ==="
  mkdir -p "$DEPLOY_DIR"
  cp -f "$OUT_DIR/wsl-bridge.exe" "$DEPLOY_DIR/wsl-bridge.exe"
  cp -f "$OUT_DIR/wsl-bridge.exe" "$DEPLOY_DIR/bash.exe"
  cp -f "$OUT_DIR/wsl-bridge.exe" "$DEPLOY_DIR/sh.exe"
  ls -lh "$DEPLOY_DIR/wsl-bridge.exe" "$DEPLOY_DIR/bash.exe" "$DEPLOY_DIR/sh.exe"
fi
