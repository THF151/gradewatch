#!/usr/bin/env bash
set -euo pipefail

binary=${1:?usage: smoke-package.sh <binary> <amd64|arm64>}
arch=${2:?usage: smoke-package.sh <binary> <amd64|arm64>}
host=$(uname -m)
case "$arch" in
  amd64) machine="Advanced Micro Devices X86-64"; native=x86_64 ;;
  arm64) machine="AArch64"; native=aarch64 ;;
  *) printf 'Unexpected package architecture: %s\n' "$arch" >&2; exit 1 ;;
esac

headers=$(LC_ALL=C readelf -h -l "$binary")
if [[ "$headers" != *"Machine:"*"$machine"* || "$headers" == *INTERP* ]]; then
  printf '%s is not a static %s binary\n' "$binary" "$arch" >&2
  exit 1
fi

command=("$binary")
if [[ "$arch" == arm64 && "$host" == x86_64 ]]; then
  command=(buildkit-qemu-aarch64 "$binary")
elif [[ "$host" != "$native" ]]; then
  printf 'No smoke-test runtime for %s on %s\n' "$arch" "$host" >&2
  exit 1
fi

export DATA_DIR MASTER_KEY ADMIN_PASSWORD_HASH_B64
DATA_DIR=$(mktemp -d)
trap 'rm -rf -- "$DATA_DIR"' EXIT
MASTER_KEY=$(openssl rand -base64 32)
ADMIN_PASSWORD_HASH_B64=$("${command[@]}" --hash-password-b64 ci-smoke-fixture)
"${command[@]}" --healthcheck
