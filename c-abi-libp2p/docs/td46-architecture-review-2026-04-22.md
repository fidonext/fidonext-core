# TD-46 architecture review (2026-04-22)

Tracker: NIM-88. Ship-gate5 FAIL. Previous triage (`td46-multiaddr-sigsegv-triage-2026-04-22.md`) proposed `libp2p-swarm 0.47.0 -> 0.47.1` (hashlink LRU swap). Applied; ship-gate5 crashed with identical backtrace. This doc is the architectural call on how to proceed.

## 1. Re-reading the crash

Both tombstones, bit-for-bit on frames #00..#05:

```
#00 multiaddr::protocol::Protocol::from_bytes   (x0 = NULL slice data_ptr)
#01 <multiaddr::Iter as Iterator>::next
#02 <Multiaddr as MultiaddrExt>::is_relayed
#03 libp2p_relay::priv_client::Behaviour::handle_established_outbound_connection
#04 cabi_rust_libp2p::transport::NetworkBehaviour::handle_established_outbound_connection (derive)
#05 libp2p_swarm::Swarm::poll_next_event
```

Two observations drop the "heap corruption in `libp2p-swarm` peer-address LRU" hypothesis:

- The swarm hands `handle_established_outbound_connection` the **`ConnectedPoint`** of the just-established connection (the multiaddr we dialed), not a reference into any peer-address cache. The multiaddr at frame #02 is the dial-target address the swarm just finished upgrading, owned by the connection-establishment event payload. It is not an `&` into the LRU.
- PR 6138 (0.47.1) changed `peer_addresses.rs`. That module's frames do not appear on the stack. Swapping the LRU changed nothing because the LRU was never on the crashing path.

What the frame actually says: `libp2p-relay`'s client-side `NetworkBehaviour` impl runs `dialed_addr.is_relayed()` on every outbound-established event to decide whether the new connection is a relay circuit or a direct dial — so relay-reservation bookkeeping only advances on direct dials and circuit replies are routed differently. `is_relayed` iterates the multiaddr's bytes looking for `Protocol::P2pCircuit`. It crashes when `multiaddr::Iter::next` reaches `Protocol::from_bytes` with a slice whose `data_ptr` is NULL and `len > 0`.

The safe-Rust `Multiaddr` type stores bytes in `Arc<Vec<u8>>`. There is no safe path to a NULL data pointer with positive length. Three places can produce one:

(a) FFI — someone reads C bytes into a `&[u8]` via `std::slice::from_raw_parts(ptr, len)` where `ptr = NULL` and `len > 0`. Our JNI path does this pattern for `dequeueMessage` etc., but the multiaddr argument here is constructed entirely inside Rust by `libp2p`.
(b) Heap corruption / UAF — something freed the `Vec<u8>` behind the multiaddr while the swarm was holding a reference and a later alloc scribbled the `data` field. Possible but requires a concrete UB site.
(c) `libp2p-relay` client internally constructs a synthetic `Multiaddr` and hands it to `is_relayed` on a path that is only reached for a specific wire pattern. In `libp2p-relay 0.21.x` the priv_client builds an inner circuit multiaddr by concatenating prefix + `P2pCircuit` + `P2p(target)` via `Multiaddr::push`. A prefix with zero-length bytes plus an unusual p2p-circuit STUN/observed-addr reply on the relay reservation stream could arrive at `handle_established_outbound_connection` still referencing a freshly-decoded relay-reservation frame whose inner address slice was CBOR-decoded with `len > 0` from an empty buffer. This needs upstream confirmation but it fits the shape: VPN-specific, post-reservation, intermittent.

## 2. Why it only hits under amnezia VPN, post-DHT

Ship-gate3 (clean), ship-gate4 (48s bootstrap dial crash), ship-gate5 (261s post-publish crash). VPN is constant across all three; the variable is which peer we dial and how its `ConnectedPoint` is shaped.

- ship-gate4 dialed the 3 hardcoded bootstrap relays over tun0. One of those dials produced the bad multiaddr.
- ship-gate5 (after the noise of the Cargo.lock churn) gets through bootstrap and crashes on a **DHT-discovered peer**. The bad multiaddr is now synthesized by our own DHT / kademlia peer-routing output path OR by a relay-circuit reply on a newly minted reservation.

The 0.47.1 patch shifted allocation/timing enough to reorder which dial crashes first. It did not remove the crash source.

The common factor across both failure modes is `relay_client.handle_established_outbound_connection` being invoked on a multiaddr the relay_client has never seen before AND whose inner byte buffer is malformed. On a06 (no VPN) either the malformed buffer never appears, or the swarm never reaches that `is_relayed` call on the same wire shapes (MTU 1500 vs amnezia's 1376 matters for CBOR / varint truncation edge cases).

## 3. Why Option B (disable identify remote-address push) will NOT fix this

The residual-risk note in the prior triage doc proposed disabling identify's remote-address push. The identify behaviour's push path feeds `listen_addrs` and `observed_addr` into peer-address state. But:

- `libp2p-relay 0.21.x`'s client behaviour does **not** read from the identify cache inside `handle_established_outbound_connection`. The multiaddr it inspects is the dial's own `ConnectedPoint::dialed_addr`, owned by the connection-established event and built by the transport.
- Disabling identify push reduces address-pool churn, but the crash isn't caused by cache churn — it's caused by a specific wire input reaching `Multiaddr::Iter` with a NULL-but-nonempty slice descriptor.
- Our own identify-received handler (`manager.rs:3082`) adds `info.listen_addrs` to Kademlia **via clone**, not via holding a reference — even if the source multiaddr were bad, our copy path would fault on the clone, not much later inside the relay client.

Option B is cargo-cult defense against a hypothesis we already know is wrong. **Rejected.**

## 4. What would actually mitigate

The narrow fix is in the relay-client path: guard against malformed multiaddrs at the boundary. Two architectural places to do that:

### (i) Local patched libp2p-relay

Fork `libp2p-relay` to version-pin, add `if dialed_addr.iter().count() == 0 { return Ok(...); }` or a `catch_unwind` at the `is_relayed` site and log. This is the smallest upstream-compatible defensive patch. Cost: we now maintain a libp2p fork. We already pin 0.21.1; extending to a 0.21.1+fidonext1 is doable and auditable. The crash goes from SIGSEGV to a logged warning. Users stay online.

### (ii) Transport-level sanitation

Wrap the transport so every `StreamMuxerBox` emission re-validates its reported multiaddr via `Multiaddr::try_from(addr.to_vec())` before handing to the upgrade chain. If validation fails, drop the connection. This is expensive (validates every connection) and does not obviously catch the bug — because the defective multiaddr is being iterated, it probably **does** validate via `try_from` and only fails the later byte-pointer invariant, which points at UB deeper down. Skip.

### (iii) Hard isolation — disable the relay-client entirely on amnezia-detected networks

The clean engineering answer for v0.0.7 is: detect VPN / MTU anomaly at startup and fall back to a libp2p swarm built without the `relay::client::Behaviour` (leave the relay *transport* in the stack so we can still dial `/p2p-circuit` addresses via the boxed transport, but drop the client-side NetworkBehaviour that holds `handle_established_outbound_connection`). Concretely: when amnezia is active, `hop_relay = false` AND `relay_client_behaviour` is gated behind a new `TransportConfig.enable_relay_client` flag.

Cost: on VPN users we lose automatic relay reservations and their reachability collapses to "direct-dialable peers only". For M2 the only affected capability is reach into a firewalled peer via our relay fleet; they can still message anyone directly dialable and still receive messages when any peer dials them. This is a real scope degradation but it's localized and correct: if our relay-client composition faults on VPN traffic, the architecturally correct response is to not compose it for VPN users until we can debug the upstream bug.

### (iv) Upstream-first, stop shipping until fixed

Hold v0.0.7 until rust-p2p-engineer and/or upstream produce a real root-cause and patch. This is the "A" path from the user's prompt.

## 5. Recommendation: Option C modified — ship (iii), pursue debug-libcabi triage on (A)

The user's stated Option C was "ship B for v0.0.7, debug A for v0.0.8". Option B is wrong (see §3). The right Option C is:

> **Ship v0.0.7 with `enable_relay_client = false` when amnezia VPN is detected at Android-side service start, with a user-facing banner explaining reduced connectivity on VPN. Simultaneously, kick off the Option A deep-triage (debug libcabi, TRACE-level multiaddr logs, upstream issue with the exact wire frame) for v0.0.8.**

Rationale:

- The crash is load-bearing for VPN users but does not affect a06-class users. The ship-gate5 timing shift proves it's not a hard block for announceSelf or DHT publish — kunzite got through both — but it IS a hard block for keeping the service alive past ~4 minutes under VPN. Shipping without any mitigation would mean "FidoNext crashes on amnezia users in 4 minutes, 100 %".
- Disabling the relay-client NetworkBehaviour on VPN-only is a small, reviewable diff in `transport/libp2p.rs` + `TransportConfig` + a one-call JNI addition from Android (`libp2p_set_enable_relay_client(bool)`) before `libp2p_init`. Zero wire protocol change. No E2EE touched.
- The v0.0.8 plan gets the correct fix: build a debug libcabi with `RUST_LOG=libp2p_relay=trace,multiaddr=trace,libp2p_swarm=debug`, run kunzite + amnezia for 10 minutes, dump the exact multiaddr bytes fed into `is_relayed`, construct a minimal repro outside our app, file upstream.

## 6. C-ABI delta

One new FFI, polling-compatible (it's a setter, not a stream). Old / new signatures:

```c
/* NEW, v0.0.7 */
int libp2p_set_enable_relay_client(int enable);  /* call BEFORE libp2p_init; returns 0 on success */
```

No callback, no new queue, no header shape change beyond the one new extern "C" symbol. Header bump from ABI version N -> N+1 (additive). `cabi-rust-libp2p.h` gets one new declaration; the JNI wrapper gets one new native-method binding in `RustNative.kt` + one call in `libp2p_jni.c` that forwards an `int`. No migration for existing callers — default stays `true`.

## 7. Risks we're sleeping on

1. **We compose libp2p protocols by hand and we don't unit-test the composition under adversarial transport conditions.** The amnezia MTU (1376) is not exotic — every commercial VPN does something like it. We don't have a loopback test that runs our full swarm over an MTU-shaped tun interface. This class of bug will recur until we add that test harness.
2. **The relay-client is load-bearing for M2 reachability and we don't have a circuit-breaker for it.** Crash-looping a tokio worker takes the whole service down because we run a single multi-thread runtime for the swarm + the JNI pumps. A dedicated swarm supervisor that can restart the Behaviour (or at least drop the relay_client piece) on panic would turn crashes into logged degradations. Worth a design doc for M2.2.
3. **Cbindgen / FFI boundary is not under suspicion here** — the bad multiaddr is purely Rust-internal at the crash site. But the fact that we hand `Vec<u8>` across the C ABI via `from_raw_parts` for messages means the same NULL+len>0 shape could happen at OUR boundary. Worth an audit of every `from_raw_parts` call site in `lib.rs` as a side quest.
4. **cargo update as "investigation tool"** — ship-gate5 confirms that bumping deps based on changelog archaeology is not a substitute for actually reading the crashing code and the logs it would produce under TRACE. rust-p2p-engineer's next attempt must start with a debug build + trace logs, not another Cargo.lock edit.

## 8. Assignments

- **rust-p2p-engineer**:
  1. Add `TransportConfig.enable_relay_client: bool` (default `true`) and gate the `relay::client::Behaviour` behind it in `build_behaviour`. The relay *transport* stays in the stack so circuit multiaddrs can still be dialed as plain dials; only the NetworkBehaviour half is omitted.
  2. Add `libp2p_set_enable_relay_client(int)` to the C ABI + header.
  3. Build arm64-v8a cdylib, publish sha256.
  4. In parallel: produce a debug (non-release) libcabi + a test-only path that logs every multiaddr handed into `handle_established_outbound_connection` at its byte level, for the v0.0.8 triage.
- **android-engineer**:
  1. Detect amnezia (existing VPN-state check already flags `tun0` + `AmneziaVPN` session, surfaced in env.txt). At `Libp2pService` start, if amnezia is active, call `libp2p_set_enable_relay_client(0)` before `libp2p_init`.
  2. Surface a one-line banner in MainActivity: "Running in VPN-safe mode. Relay reachability disabled." with a learn-more link to a short FAQ doc.
  3. No schema change, no AIDL change.
- **e2e-qa-engineer**:
  1. ship-gate6 on kunzite with VPN on + `enable_relay_client=false`. Exit criterion: 10-minute burn-in, 0 SIGSEGV, TD-45 race-claim validates.
  2. ship-gate6 on a06 with VPN off + `enable_relay_client=true`. Exit criterion: no regression.
- **devops-relay**: no action v0.0.7. For v0.0.8 triage we may need a relay-side logcap of the exact circuit-reservation frame that kunzite was negotiating at t+261s; hold.
- **security-crypto-engineer**: not involved, no crypto change.
- **product-owner**: sign-off that "VPN-only users get degraded reachability in v0.0.7" is an acceptable known-issue on the release notes.

## 9. Ship-gate for v0.0.7 — known-issue call

If ship-gate6 is green, v0.0.7 ships with:
- Released behaviour: non-VPN users fully functional. Amnezia-VPN users run without relay-client; they can still message, DHT-publish, and receive anything dialable. They cannot hop through our super-relays.
- Release notes flag: "Known issue: users on VPNs with sub-1500 MTU temporarily run without relay-assisted reachability to avoid a libp2p-relay crash (TD-46). Fixed in v0.0.8."
- Tracker: NIM-88 stays open, moves to `in-progress` scoped to v0.0.8.

This is an **acceptable known-issue** for v0.0.7, not a hard blocker. The alternative — holding release until we upstream-fix a rust-libp2p multiaddr bug — is multi-week and unbounded. The degradation is narrow (VPN subset), surfaced honestly, and reversed by v0.0.8.

