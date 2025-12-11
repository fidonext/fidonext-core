FROM debian:latest

# Insall necessary build stuff for C++
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Run building project
CMD ["bash", "-lc", "\
  cmake -S . -B build-docker -DCMAKE_BUILD_TYPE=Release && \
  cmake --build build-docker --config Release -j$(nproc) && \
  cp -r build-docker/* /out \
"]