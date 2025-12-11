# Building
### Builiding with MSVC
```
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### Building with GCC/clang
```
mkdir build-release
cd build-release
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```
### Building with Docker
```
docker compose up --build cpp-build
```

## Use
1. Copy .dll or .so of the cabi-rust-libp2p into folder near executable
2. Run through cmd/terminal
3. `./ping --use-quic --lport 41001 --dport 41002`
4. `./ping --use-quic --lport 41002 --dport 41001`

### Bootstrap peers
Optional bootstrapping is supported via `--bootstrap <multiaddr>`, which can be
specified multiple times. For example:

```
ping --lport 41000 --dport 41001 --bootstrap /ip4/203.0.113.1/tcp/5001/p2p/12D3KooW...
```

### Relay hop restart
The example polls AutoNAT for up to 10 seconds. If the node reports **public**
reachability, it automatically restarts with relay hop enabled, re-dials the
bootstrap peers, and continues with the ping dial.