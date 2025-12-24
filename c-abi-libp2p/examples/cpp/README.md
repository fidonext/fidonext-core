# ping (C++ ↔ Rust libp2p C-ABI)

Small C++ CLI that loads a node via Rust `cabi_rust_libp2p` lib through a C-ABI and lets you:
- run a node as **relay** or **leaf**
- `listen` on a multiaddr
- `dial` bootstrap/target peers
- send/receive payloads via an internal message queue
- (relay) optionally enable **hop relay** when AutoNAT reports PUBLIC (or force it)

## Requirements

- C++17 compiler (MSVC / clang / g++)
- CMake
- Rust shared library built:
  - Linux: `libcabi_rust_libp2p.so`
  - Windows: `cabi_rust_libp2p.dll`

## Build
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
### Quick Start
1. Copy .dll or .so of the cabi-rust-libp2p into folder near executable
2. Run through cmd/terminal
3. `./ping --role relay --force-hop --listen /ip4/0.0.0.0/tcp/41000 --seed-phrase relay-one`
4. `./ping --listen /ip4/0.0.0.0/tcp/41001 --bootstrap /ip4/<RELAY_IP>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-a --target /ip4/<PEERB_IP>/tcp/41000/p2p/<PEERB_ID>`
5. `./ping --listen /ip4/0.0.0.0/tcp/41001 --bootstrap /ip4/<RELAY_IP>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-a --target /ip4/<PEERA_IP>/tcp/41000/p2p/<PEERA_ID>`

### Running a relay + two peers (deterministic IDs)

You can pin the `PeerId` of each node by supplying either a 32-byte hex seed
(`--seed <64 hex chars>`) **or** a human-friendly seed phrase that is
deterministically expanded to 32 bytes (`--seed-phrase <string>`). This allows
you to pre-compute relay/peer multiaddrs and wire them together reproducibly:

1. Start the public relay (waits for PUBLIC AutoNAT and restarts with hop):
   ```
   ./ping --role relay --force-hop --listen /ip4/0.0.0.0/tcp/41000 --seed-phrase relay-one
   ```
   Note the `Local PeerId` printed to the console; call it `<RELAY_ID>`.

2. Start peer A with a fixed seed, dialing the relay as a bootstrap peer:
   ```
   ./ping --listen /ip4/0.0.0.0/tcp/41001 --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-a
   ```
   The logged `Local PeerId` for this node is `<PEER_A_ID>`.

3. Start peer B the same way (different seed) and bootstrap through the relay:
   ```
   ./ping --listen /ip4/0.0.0.0/tcp/41002 --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-b
   ```
   Its `Local PeerId` is `<PEER_B_ID>`.

Once the relay reports PUBLIC reachability and the peers have dialed the relay
bootstrap address, they will exchange gossipsub messages via the relay. Enter
text in either peer terminal to broadcast payloads.

### Bootstrap peers (manual)
Optional bootstrapping is also supported via `--bootstrap <multiaddr>`, which
can be specified multiple times. The example feeds these peers directly into
node creation so they are registered with Kademlia and bootstrapped immediately.

### Relay hop restart
The example polls AutoNAT for up to 10 seconds. If the node reports **public**
reachability, it automatically restarts with relay hop enabled and continues
with the ping dial using the same bootstrap list.