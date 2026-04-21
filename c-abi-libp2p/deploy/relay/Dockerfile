# syntax=docker/dockerfile:1

# TD-01 · Native Rust relay image.
#
# The prior image wrapped `examples/python/ping_standalone_nodes.py` around
# the cdylib. That wrapper never subscribed the relay node to the
# application-level gossipsub topics (notably `/fidonext/nickname-registry/v1`),
# which QA artifact `qa-artifacts/2026-04-21T2107Z-td42-shipgate-retry/`
# proved is the blocker for cross-network nickname convergence.
#
# This image compiles the `fidonext-relay` binary from
# `c-abi-libp2p/src/bin/fidonext_relay.rs` and runs it directly — no Python
# runtime, no FFI shim. The cdylib is still produced by the workspace but
# is no longer copied into the runtime stage; the relay needs the binary,
# not the library.

FROM rust:1.91 AS builder

WORKDIR /usr/src/app
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY c-abi-libp2p ./c-abi-libp2p
WORKDIR /usr/src/app/c-abi-libp2p
RUN cargo build --release --bin fidonext-relay

FROM debian:bookworm-slim

WORKDIR /app

# Runtime deps: `ca-certificates` is kept for outbound TLS fetches (Caddy ACME
# is handled at the host layer, but the relay may still talk to libp2p peers
# over /ws/tls bootstraps). `tini` would be nice but is not strictly required —
# the `fidonext-relay` process installs its own ctrl_c handler.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/c-abi-libp2p/target/release/fidonext-relay /usr/local/bin/fidonext-relay
COPY c-abi-libp2p/deploy/relay/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /usr/local/bin/fidonext-relay

# `/data` is the canonical identity-profile directory — mount a named volume
# here in compose so the PeerId is stable across image updates.
VOLUME ["/data"]

# Defaults used by the entrypoint when an env-var is unset.
ENV LISTEN_ADDR=/ip4/0.0.0.0/tcp/41000 \
    PROFILE_PATH=/data/relay.profile.json \
    FORCE_HOP=true \
    RUST_LOG=info,peer=info

ENTRYPOINT ["/app/entrypoint.sh"]
