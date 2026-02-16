# syntax=docker/dockerfile:1

FROM rust:1.91 AS builder

WORKDIR /usr/src/app
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY c-abi-libp2p ./c-abi-libp2p
WORKDIR /usr/src/app/c-abi-libp2p
RUN cargo build --release

FROM python:3.13-slim

WORKDIR /app

COPY --from=builder /usr/src/app/c-abi-libp2p/target/release/libcabi_rust_libp2p.so /usr/local/lib/
COPY c-abi-libp2p/examples/python/ping_standalone_nodes.py /app/ping_standalone_nodes.py
COPY c-abi-libp2p/examples/python/fidonext_terminal_client.py /app/fidonext_terminal_client.py
COPY c-abi-libp2p/deploy/relay/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

ENV FIDONEXT_C_ABI=/usr/local/lib/libcabi_rust_libp2p.so
ENV RUST_LOG=info,peer=info,ffi=info
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["/app/entrypoint.sh"]

