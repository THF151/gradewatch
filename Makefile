.PHONY: help fmt fmt-check check clippy test coverage build docker-build run run-once gen-master-key

help:
	@printf '%s\n' \
	  'Targets:' \
	  '  fmt            Format Rust code' \
	  '  fmt-check      Check Rust formatting' \
	  '  check          cargo check' \
	  '  clippy         Strict clippy lint' \
	  '  test           Run tests' \
	  '  coverage       Run cargo-llvm-cov (install if missing)' \
	  '  build          Release build' \
	  '  docker-build   Build Docker image' \
	  '  run            Run service locally using .env' \
	  '  run-once       Run one poll cycle using .env' \
	  '  gen-master-key Print a new base64 MASTER_KEY'

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

check:
	cargo check --all-targets --locked

clippy:
	cargo clippy --all-targets --locked -- -D warnings

test:
	cargo test --all-targets --locked

coverage:
	@if ! cargo llvm-cov --version >/dev/null 2>&1; then \
		echo 'cargo-llvm-cov is required: cargo install cargo-llvm-cov'; \
		exit 1; \
	fi
	cargo llvm-cov --all-targets --locked --html --output-dir coverage

build:
	cargo build --release --locked

docker-build:
	docker build -t gradewatch:local .

run:
	cargo run --locked

run-once:
	cargo run --locked -- --run-once

gen-master-key:
	cargo run --locked -- --gen-master-key
