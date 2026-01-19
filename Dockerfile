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
        lld \
        openjdk-21-jre-headless \
        unzip \
        wget && \
    rm -rf /var/lib/apt/lists/*

# Install cross-compilation targets
RUN rustup target add \
        x86_64-unknown-linux-gnu \
        aarch64-unknown-linux-gnu \
        x86_64-pc-windows-gnu \
        aarch64-linux-android

ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

ENV ANDROID_NDK_VERSION=27.3.13750724

# Android (NDK) setup for building arm64-v8a
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH="${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin"
RUN mkdir -p "${ANDROID_SDK_ROOT}/cmdline-tools" && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d "${ANDROID_SDK_ROOT}/cmdline-tools" && \
    mv "${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools" "${ANDROID_SDK_ROOT}/cmdline-tools/latest" && \
    rm -f /tmp/cmdline-tools.zip && \
    yes | sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" --licenses >/dev/null && \
    sdkmanager --sdk_root="${ANDROID_SDK_ROOT}" "ndk;${ANDROID_NDK_VERSION}"
ENV ANDROID_NDK_HOME="${ANDROID_SDK_ROOT}/ndk/${ANDROID_NDK_VERSION}"
RUN cargo install cargo-ndk --locked
        

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
RUN echo "Building for Android (arm64-v8a)..."
RUN cargo ndk -t arm64-v8a build --release

# Test stage - runs tests for native platform (default final stage)
FROM builder AS test
RUN cargo test --release --verbose

# Artifact collection stage
FROM builder AS artifacts
WORKDIR /app/c-abi-libp2p

# Create output directory structure
RUN mkdir -p /output/linux-x86_64-gnu \
    && mkdir -p /output/linux-aarch64 \
    && mkdir -p /output/windows-x86_64-gnu \
    && mkdir -p /output/android-arm64-v8a

# Copy Linux GNU build
RUN cp target/x86_64-unknown-linux-gnu/release/libcabi_rust_libp2p.so /output/linux-x86_64-gnu/ 2>/dev/null || true

# Copy Linux ARM64 build
RUN cp target/aarch64-unknown-linux-gnu/release/libcabi_rust_libp2p.so /output/linux-aarch64/ 2>/dev/null || true

# Copy Windows GNU build
RUN cp target/x86_64-pc-windows-gnu/release/cabi_rust_libp2p.dll /output/windows-x86_64-gnu/ 2>/dev/null || true

# Copy Android arm64-v8a build
RUN cp target/aarch64-linux-android/release/libcabi_rust_libp2p.so /output/android-arm64-v8a/ 2>/dev/null || true

# Generate C header file
RUN cargo build && \
    cp cabi-rust-libp2p.h /output/ 2>/dev/null || true