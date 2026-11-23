#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_WORKSPACE:?}"
: "${RUNNER_TEMP:?}"
cd "$GITHUB_WORKSPACE"
export RUSTUP_TOOLCHAIN=1.99.1
if [[ ${GHARP_CACHE_ENABLED:-0} == 1 ]]; then
  export ZIG_GLOBAL_CACHE_DIR=/cache/zig/0.15.2
  mkdir -p "$ZIG_GLOBAL_CACHE_DIR"
fi

started=$SECONDS
runner-target-cache restore "$GITHUB_WORKSPACE/target"
restored=$SECONDS
cargo zigbuild --release --locked \
  --target x86_64-unknown-linux-musl \
  --target aarch64-unknown-linux-musl
compiled=$SECONDS

context="$RUNNER_TEMP/gradewatch-package"
mkdir -p "$context"/{amd64,arm64,data}
install -m 0755 target/x86_64-unknown-linux-musl/release/gradewatch "$context/amd64/"
install -m 0755 target/aarch64-unknown-linux-musl/release/gradewatch "$context/arm64/"
touch "$context/data/.keep"
printf 'Cargo target restore: %ss. Cross-compile: %ss.\n' "$((restored - started))" "$((compiled - restored))"
