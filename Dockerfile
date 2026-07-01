# syntax=docker/dockerfile:1

FROM rust:slim-bookworm AS build
ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN case "${TARGETARCH:-$(uname -m)}" in \
      amd64|x86_64) echo x86_64-unknown-linux-musl > /tmp/rust-target ;; \
      arm64|aarch64) echo aarch64-unknown-linux-musl > /tmp/rust-target ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && rustup toolchain install stable --profile minimal --target "$(cat /tmp/rust-target)"
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY migrations ./migrations
COPY templates ./templates
COPY src ./src
COPY tests ./tests
RUN target="$(cat /tmp/rust-target)" \
    && cargo +stable build --release --locked --target "$target" \
    && cp "target/$target/release/gradewatch" /app/gradewatch \
    && mkdir -p /tmp/gradewatch-data \
    && touch /tmp/gradewatch-data/.keep

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app/gradewatch /gradewatch
COPY --from=build --chown=65532:65532 /tmp/gradewatch-data /data
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/gradewatch"]
