# TD-46 — Multiaddr SIGSEGV triage (2026-04-22)

Tracker: NIM-88. v0.0.7 ship-gate blocker. Uncovered by ship-gate4
(`fidonext_android/qa-artifacts/2026-04-22T1313Z-ship-gate4/`) on
kunzite+a06. Blocks TD-45 / NIM-87 revalidation because kunzite's
foreground service dies in the bootstrap dial path before any nickname
claim runs.

## Crash signature

- Signal: `SIGSEGV` / `SEGV_MAPERR` / fault addr `0x0`, `Cause: null pointer dereference`.
- Thread: `tokio-runtime-w` (tid 9839, pid 26354).
- libcabi (ship-gate4 build) sha256: `12b430dc361e94318267d453cd4bd279f9fcace8b12a2f7794a831d47bbd9229`.
- Symbolicated top of stack:

```
#00 multiaddr::protocol::Protocol::from_bytes      (x0=0, NULL slice data_ptr)
#01 <multiaddr::Iter as Iterator>::next
#02 <Multiaddr as MultiaddrExt>::is_relayed        (libp2p_relay::multiaddr_ext)
#03 libp2p_relay::priv_client::Behaviour::handle_established_outbound_connection
#04 cabi_rust_libp2p::transport::NetworkBehaviour::handle_established_outbound_connection (derive)
#05 libp2p_swarm::Swarm::poll_next_event
```

Fires during early bootstrap on the first relay-client-observed
outbound connection. On a06 (no VPN) the code paths poll cleanly and
`announceSelf` completes. On kunzite (amnezia VPN active) the tokio
worker aborts with a NULL data pointer being chased through
`Iter::next` / `Protocol::from_bytes`.

## Cargo.lock bisect

Last commit touching `c-abi-libp2p/Cargo.lock`: `8ad0fbb` (TD-01 relay
binary), weeks before ship-gate3. No uncommitted changes before this
triage. The TD-45 rebuild ran against the exact same dep tree as
ship-gate3. Pre-fix versions on the crash path:

| Crate          | Version |
| -------------- | ------- |
| `libp2p`       | 0.56.0  |
| `libp2p-core`  | 0.43.1  |
| `libp2p-swarm` | 0.47.0  |
| `libp2p-relay` | 0.21.0  |
| `multiaddr`    | 0.18.2  |
| `lru`          | 0.12.5  |

**No dep bump between ship-gate3 and ship-gate4.** Latent bug, not a
TD-45 regression. The TD-45 diff is entirely in `src/peer/manager.rs`
(nickname-claim tiebreak) — not on the crashing stack and semantically
independent of the transport layer.

## Root-cause hypothesis

`multiaddr::Iter::next` guards `self.0.is_empty()` before
`Protocol::from_bytes`, so reaching `from_bytes` with `x0 = NULL`
implies the iterator is reading a `&[u8]` whose data pointer is null
with `len > 0`. Every public `Multiaddr` constructor validates bytes
(`TryFrom<Vec<u8>>`, `FromStr`, …) and stores them in
`Arc<Vec<u8>>`, which cannot produce a null data pointer from safe
Rust. The crash therefore indicates heap corruption / use-after-free
of the `Arc<Vec<u8>>` backing a `Multiaddr` held by either the
`libp2p-swarm` peer-address cache or the relay-client dial state.

`libp2p-swarm 0.47.0` uses `lru::LruCache` in
`src/behaviour/peer_addresses.rs` to track peer→addr mappings. The
`lru 0.12.x` crate has known Miri-reported UB in eviction paths, and
the next patch release — `libp2p-swarm 0.47.1` — replaces
`lru::LruCache` with `hashlink::LruCache` in exactly that module
(CHANGELOG: "Replace `lru::LruCache` with `hashlink::LruCache`", PR
6138). Clean, minimal-diff bump whose changelog wording plus the
crash site (peer-address iteration on an outbound relay-client
connection under a non-standard VPN route) points strongly at the
replaced LRU as the corruption source.

The amnezia VPN makes kunzite a reliable reproducer by reshaping the
dial-order / identify-push cadence so the LRU eviction hits at exactly
the wrong moment while the relay client holds a `&Multiaddr` into it.

## Fix applied

`cargo update -p libp2p-swarm --precise 0.47.1` then
`cargo update -p libp2p-relay --precise 0.21.1`. No `Cargo.toml`
change (our dep is `libp2p = "0.56"`, both are semver-compatible
patches):

| Crate              | Before  | After     |
| ------------------ | ------- | --------- |
| `libp2p-core`      | 0.43.1  | 0.43.2    |
| `libp2p-swarm`     | 0.47.0  | 0.47.1    |
| `libp2p-relay`     | 0.21.0  | 0.21.1    |
| `lru`              | 0.12.5  | (dropped) |
| `hashlink`         | –       | 0.10.0    |
| `allocator-api2`   | 0.2.21  | (dropped) |

Only `Cargo.lock` changes. `libp2p-relay 0.21.1` is a trivial
`get_or_insert` → `get_or_insert_with` allocation tweak (not the fix,
but picked up as the matching patch release). `libp2p-core 0.43.2` is
bundled by the resolver; diff touches `peer_record.rs` and
`transport.rs`, no behavioural change on the crashing path. The
load-bearing change is `libp2p-swarm 0.47.1`'s LRU swap in
`src/behaviour/peer_addresses.rs`.

No core source change. No header regeneration — `git diff
cabi-rust-libp2p.h` is empty. No E2EE code touched, so no
security-crypto-engineer review needed.

## Build / test

- `cargo build --release` — clean.
- `cargo test --release --lib` — `101 passed; 0 failed; 1 ignored`.
  All TD-15 / TD-37 / TD-40 / TD-42 / TD-44 / TD-45 nickname-registry
  tests remain green, all avatar-fetch tests pass, all
  messaging/schema tests pass.
- `cargo ndk -t arm64-v8a build --release --lib` — clean against NDK
  27.0.12077973. (The `fidonext-relay` bin fails local link because
  `getifaddrs`/`freeifaddrs` are absent from the bionic available
  locally; pre-existing, unrelated — the bin is host-only, CI builds
  it only on Linux x86_64/aarch64. The cdylib used by Android is
  unaffected.)

## Artifact

- New libcabi: `fidonext_android/app/src/main/jniLibs/arm64-v8a/libcabi_rust_libp2p.so`
  sha256 `4d13d3b8fd7029ba8b8c99909df2892ed8620a20a47e5ac31c562975ca886d79`
  (was `12b430dc361e94318267d453cd4bd279f9fcace8b12a2f7794a831d47bbd9229`).

## Residual risk

The root-cause hypothesis — LRU-backed peer-address cache corruption —
is strong but unproven without a Miri/ASan reproducer against the
exact VPN-mangled identify/push sequence. If ship-gate5 still crashes
on kunzite with the same backtrace under VPN:

1. File an upstream `rust-libp2p` issue with the kunzite tombstone and
   ship-gate5 repro log; include the observation that this same build
   does not crash on a06.
2. As a defensive local mitigation, consider disabling `identify`'s
   remote-address push contributions on our swarm (we already rely on
   AutoNAT + Kademlia for reachability), which would bypass the
   peer-address LRU path implicated by the hypothesis. That mitigation
   touches `src/transport/libp2p.rs` and would need architect
   sign-off; held off unless ship-gate5 reproduces.

## Exit-criteria checklist

- [x] Bisect output documented.
- [x] Fix applied (patch-level Cargo.lock bump).
- [x] libcabi arm64-v8a rebuilt and dropped into
      `fidonext_android/app/src/main/jniLibs/arm64-v8a/`.
- [x] New sha256 recorded.
- [x] No header change (verified; `git diff cabi-rust-libp2p.h` empty).
