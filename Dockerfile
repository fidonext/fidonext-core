# Dockerfile for building and testing the Rust libp2p project for multiple platforms
# 
# Usage:
#   Build and test for all platform: docker build -t pheonx-libp2p .
#   Test for all platforms: docker build -t pheonx-libp2p --target test .


# Use the official Rust image as base
FROM rust:1.91 AS builder

# Install cross-compilation toolchains and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang \
        gcc-aarch64-linux-gnu \
        gcc-mingw-w64 \
        libc6-dev-arm64-cross \
        lld && \
    rm -rf /var/lib/apt/lists/*

# Install cross-compilation targets
RUN rustup target add \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu \
        x86_64-pc-windows-gnu

ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
        

# Set working directory
WORKDIR /app

# Copy the entire project structure
COPY c-abi-libp2p ./c-abi-libp2p/

# Navigate to the project directory
WORKDIR /app/c-abi-libp2p/

# Build for all platforms
RUN echo "Building for Linux (GNU)..."
RUN cargo build --release --target x86_64-unknown-linux-gnu
RUN echo "Building for Linux (ARM64)..."
RUN cargo build --release --target aarch64-unknown-linux-gnu
RUN echo "Building for Windows (GNU)..."
RUN cargo build --release --target x86_64-pc-windows-gnu

# Test stage - runs tests for native platform (default final stage)
FROM builder AS test
RUN cargo test --release --verbose

# Artifact collection stage
FROM builder AS artifacts
WORKDIR /app/c-abi-libp2p

# Create output directory structure
RUN mkdir -p /output/linux-x86_64-gnu \
    && mkdir -p /output/linux-x86_64-musl \
    && mkdir -p /output/linux-aarch64 \
    && mkdir -p /output/windows-x86_64-gnu

# Copy Linux GNU build
RUN cp target/x86_64-unknown-linux-gnu/release/libcabi_rust_libp2p.so /output/linux-x86_64-gnu/ 2>/dev/null || true

# Copy Linux musl build
RUN cp target/x86_64-unknown-linux-musl/release/libcabi_rust_libp2p.a /output/linux-x86_64-musl/ 2>/dev/null || true

# Copy Linux ARM64 build
RUN cp target/aarch64-unknown-linux-gnu/release/libcabi_rust_libp2p.so /output/linux-aarch64/ 2>/dev/null || true

# Copy Windows GNU build
RUN cp target/x86_64-pc-windows-gnu/release/cabi_rust_libp2p.dll /output/windows-x86_64-gnu/ 2>/dev/null || true

# Generate C header file
RUN cargo build && \
    cp cabi-rust-libp2p.h /output/ 2>/dev/null || true