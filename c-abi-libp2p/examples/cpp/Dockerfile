#
# Build linux/amd64 Rust C-ABI library, then build the C++ client that dlopen()s it.
#
# Recommended invocation (from repo root):
#
#   docker buildx build --platform linux/amd64 \
#     -f c-abi-libp2p/examples/cpp/Dockerfile \
#     --target artifacts \
#     --output type=local,dest=./c-abi-libp2p/examples/cpp/dist \
#     .
#

FROM --platform=linux/amd64 rust:1.91 AS rust_builder

WORKDIR /build
COPY  ./ ./

# Explicit target so the output path is stable under target/<triple>/...
RUN cargo build --release --target x86_64-unknown-linux-gnu


FROM --platform=linux/amd64 debian:bookworm AS cpp_builder

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY ./examples/cpp ./

RUN cmake -S . -B build-docker -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build-docker --config Release -j"$(nproc)"


FROM --platform=linux/amd64 debian:bookworm-slim AS runtime
WORKDIR /app

# Required for the dynamically-linked Rust .so and C++ binary
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgcc-s1 \
    iproute2 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=rust_builder /build/target/x86_64-unknown-linux-gnu/release/libcabi_rust_libp2p.so /app/
COPY --from=cpp_builder /build/build-docker/ping /app/

CMD ["/app/ping", "--use-quic", "--lport", "41001", "--dport", "41002"]