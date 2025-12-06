# syntax=docker/dockerfile:1

# Build stage for the Rust shared library
FROM rust:1.91 AS builder

WORKDIR /usr/src/app

# Copy the C-ABI project
# We assume the build context is the root of the repo
COPY c-abi-libp2p ./c-abi-libp2p

WORKDIR /usr/src/app/c-abi-libp2p

# Build the shared library in release mode
RUN cargo build --release

# Runtime stage
FROM python:3.13-slim

WORKDIR /app

# Copy the compiled shared library from the builder stage
COPY --from=builder /usr/src/app/c-abi-libp2p/target/release/libcabi_rust_libp2p.so /usr/local/lib/

# Set the environment variable so the Python script finds the library
ENV FIDONEXT_C_ABI=/usr/local/lib/libcabi_rust_libp2p.so
ENV RUST_LOG=info,peer=info,ffi=info
ENV PYTHONUNBUFFERED=1

# Copy the Python example scripts
COPY c-abi-libp2p/examples/python/ping_standalone_nodes.py .

# Entrypoint
ENTRYPOINT ["python3", "ping_standalone_nodes.py"]

