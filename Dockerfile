# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage: compile a static musl binary.
#
# rust:alpine's host target is *-unknown-linux-musl, which links crt-static by
# default, so the release binary has no shared-library dependencies and runs on
# a bare alpine (or even scratch) runtime. ring builds fine under musl; it only
# needs a C toolchain, which musl-dev provides.
# ---------------------------------------------------------------------------
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

# Strip symbols at link time so we don't depend on a separate `strip` binary.
ENV RUSTFLAGS="-C strip=symbols"

WORKDIR /build

# Only the inputs the build actually consumes, so edits to README/learning/etc.
# never bust the dependency cache.
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# BuildKit cache mounts keep the crate registry and target dir warm across
# rebuilds. The binary is copied out of the (ephemeral) target cache mount into
# an image layer within the same RUN, while the mount is still attached.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked \
 && cp target/release/russl /usr/local/bin/russl

# ---------------------------------------------------------------------------
# Runtime stage: minimal alpine + CA roots, non-root.
# ---------------------------------------------------------------------------
FROM alpine:3

# ca-certificates is required, not optional: rustls-native-certs loads the OS
# trust store, and --ocsp / --ct / --connection (HSTS) perform real HTTPS chain
# verification. Without roots those features find nothing to trust.
RUN apk add --no-cache ca-certificates \
 && addgroup -S russl \
 && adduser -S -G russl -H -s /sbin/nologin russl

COPY --from=builder /usr/local/bin/russl /usr/local/bin/russl

USER russl

ENTRYPOINT ["russl"]
