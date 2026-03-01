# ping (C++ standalone ↔ Rust libp2p C-ABI)

`examples/cpp/ping` now mirrors the core standalone scenario of
`examples/python/ping_standalone_nodes.py`: same primary role/transport/identity
switches, same relay hop decision flow (force-hop vs AutoNAT wait), and a
matching interactive/receive-only console lifecycle.

## Supported CLI options (parity scope)

- `--role relay|leaf` (default: `leaf`)
  - `relay`: can enable hop relay support.
  - `leaf`: regular peer behavior.
- `--use-quic`
  - Uses QUIC transport and defaults listen address to
    `/ip4/127.0.0.1/udp/41000/quic-v1`.
- `--use-ws`
  - Uses WebSocket transport via `cabi_node_new_v2` and defaults listen address
    to `/ip4/127.0.0.1/tcp/41000/ws`.
  - Mutually exclusive with `--use-quic`.
- `--force-hop`
  - Relay-only: start with hop enabled immediately (no AutoNAT wait).
- `--listen <multiaddr>`
  - Explicit listen multiaddr (overrides transport-based defaults).
- `--bootstrap <multiaddr>` (repeatable)
  - Peers used for startup dial and relay reservation fallback.
- `--target <multiaddr>` (repeatable)
  - Additional peers dialed after bootstrap peers.
- `--seed <64-hex>`
  - Deterministic 32-byte identity seed.
- `--seed-phrase <text>`
  - Deterministic 32-byte identity seed derived from text.
  - Mutually exclusive with `--seed`.

> Note: Python standalone has many extra flags (manifest/known-peers/libsignal/scripted message).
> The C++ example intentionally keeps parity for the standalone ping workflow
> available through this ABI demo.

## Runtime flow (Python-aligned order)

1. Parse/normalize CLI arguments.
2. Create node with initial hop policy:
   - relay + `--force-hop` => hop enabled at creation;
   - otherwise hop disabled initially.
3. Print `Local PeerId`.
4. Listen on selected multiaddr (`Attempting to listen...` then `Listening on ...`).
5. Relay role:
   - `--force-hop`: print force-hop confirmation;
   - otherwise wait up to 10s for PUBLIC AutoNAT:
     - on `PUBLIC`: print `AutoNAT: PUBLIC`, restart node with hop enabled,
       print `Local PeerId`, listen again;
     - on timeout/non-public: print continuation message and attempt relay
       reservations on bootstrap peers.
6. Dial bootstrap peers, then target peers.
7. Start receive loop and then:
   - interactive stdin: prompt/send loop;
   - non-interactive stdin: receive-only mode until Ctrl+C.

## Console UX expectations

- Core status lines are aligned with Python semantics and ordering:
  - `Local PeerId: ...`
  - `Attempting to listen on ...`
  - `Listening on ...`
  - `Waiting up to 10s for PUBLIC AutoNAT status before enabling relay hop...`
  - `AutoNAT: PUBLIC|PRIVATE|UNKNOWN`
  - `AutoNAT PUBLIC detected. Restarting relay with hop enabled.`
  - `AutoNAT did not report PUBLIC; continuing without hop.`
  - `Dialed bootstrap peer: ...`, `Dialed target peer: ...`
  - `Received payload: '...'`
  - `Enter payload (empty line or /quit to exit):`
  - `STDIN is non-interactive; running receive-only mode. Press Ctrl+C to exit.`

## Build

### MSVC / Visual Studio

```bash
cmake -S . -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

### GCC / Clang

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

### Docker example build

```bash
docker compose up --build cpp-build
```

## Run scenarios

1. Relay (forced hop):

```bash
./ping --role relay --force-hop --listen /ip4/0.0.0.0/tcp/41000 --seed-phrase relay-one
```

2. Leaf A bootstrapping via relay:

```bash
./ping --listen /ip4/0.0.0.0/tcp/41001 --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-a
```

3. Leaf B bootstrapping via relay and dialing A:

```bash
./ping --listen /ip4/0.0.0.0/tcp/41002 --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> --seed-phrase peer-b --target /ip4/<peer-a-ip>/tcp/41001/p2p/<PEER_A_ID>
```

4. WebSocket transport variant:

```bash
./ping --role relay --use-ws --listen /ip4/0.0.0.0/tcp/41000/ws --force-hop
```

## Platform notes

- Dynamic loading abstraction (`dyn_lib.*`) is preserved; no Linux-only runtime
  dependency was introduced.
- Default library name remains platform-specific:
  - Windows: `cabi_rust_libp2p.dll`
  - non-Windows: `./libcabi_rust_libp2p.so`
