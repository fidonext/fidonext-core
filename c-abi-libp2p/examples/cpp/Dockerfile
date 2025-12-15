FROM debian:latest AS builder

# Insall necessary build stuff for C++
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    cmake \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY ./ ./

RUN cmake -S . -B build-docker -DCMAKE_BUILD_TYPE=Release
RUN cmake --build build-docker --config Release -j$(nproc)


FROM gcr.io/distroless/cc-debian12 AS runtime

WORKDIR /app

COPY ./cabi_rust_libp2p.* /app/
COPY --from=builder /build/build-docker/ping /app/

CMD ["/app/ping", "--use-quic", "--lport", "41001", "--dport", "41002"]