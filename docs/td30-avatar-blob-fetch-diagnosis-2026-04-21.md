# TD-30 — avatar blob-fetch `status=13` on Bob side

**Date:** 2026-04-21
**Author:** e2e-qa-engineer
**Scope:** Diagnose why Bob's `cabi_node_fetch_avatar` returns `status=13` on every retry.
**Verdict:** Not an avatar-handler bug. Root cause is that Bob cannot reach Alice on any multiaddr — direct dials fail (LAN-only listeners) and the **relay-circuit fallback is absent from the outbound dial path**. `cabi_node_reserve_relay` exists as a C ABI symbol but is wired into neither the Android JNI layer nor the core's own startup / autonomous dialing loop.

## Scenario summary

Two arm64-v8a emulators (5554 / 5556), fresh installs of debug APK built on top of libcabi with TD-29 tracing. Alice sets her profile (name/nick/avatar, 182-byte PNG, sha256 `f43586a1...`). Bob adds Alice by peer_id; profile record fetches from DHT cleanly; `ProfileSyncCoordinator` then kicks off the TD-22 retry schedule (0/5/15/30 s) for the avatar blob. All four calls return `status=13`.

Peer IDs:
- Alice: `12D3KooWFUBpUgGywZPur3ayuX1XrTi1xX1WZT5ighvvRKuxfEX4`
- Bob:   `12D3KooWSFJz26VSppSgQowTwYfWacTV8sZSsrjGRBAsZBgu5JpG`

## Phase 0 — tracing-android plumbing

PASS. `adb logcat | grep -i fidonext` returns native entries right after `Libp2pService` starts, with the expected three modules (`libp2p_swarm`, `peer`, `libp2p_kad`) all emitting under the `fidonext` tag. RUST_LOG is successfully applied via `android.system.Os.setenv` before `System.loadLibrary`.

```
04-21 13:53:27.303 I fidonext: libp2p_swarm: local_peer_id=12D3KooWFUBp...fEX4
04-21 13:53:27.303 I fidonext: peer: adding bootstrap peerpeer_id=12D3KooWPmi5... address=/ip4/217.65.5.134/tcp/41000
04-21 13:53:27.316 D fidonext: peer: kademlia eventother=RoutingUpdated { peer: PeerId("12D3KooWPmi5..."), is_new_peer: true, addresses: [...], old_peer: None }
04-21 13:53:27.347 I fidonext: peer: started get_closest_peers querypeer_id=...
```

## Phase 1 — Alice `setSelfAvatar` (register provider)

PASS. Sequence is tight and correct.

```
04-21 13:55:44.127 I ProfileSyncCoordinator: setSelfAvatar: path=/data/user/0/.../self_avatar.png bytes=182 sha256=f43586a1...84cddab
04-21 13:55:44.138 I fidonext: peer: self avatar stored; will serve on /fidonext/blob-fetch/1.0.0 avatar_sha256=f43586a1...
04-21 13:55:44.139 I ProfileSyncCoordinator: setSelfAvatar: ok, native sha256=f43586a1...
04-21 13:55:44.143 I ProfileSyncCoordinator: publishProfileRecord: peerId=...fEX4 name="Alice TD30 debug" nick="alice_td30" avatarSha256=f43586a1... ttlSec=2592000
```

Alice's side registered the bytes with libcabi and confirmed the provider role on `/fidonext/blob-fetch/1.0.0`. H1 refuted.

## Phase 2 — Bob `fetchAvatar` + Alice handler window

Bob's side (request-response dispatches fine; dial fails).

```
04-21 13:57:55.118 D fidonext: peer: dispatched blob fetch requestpeer=12D3KooWFUBp...fEX4 blob_sha256=f43586a1... request_id=OutboundRequestId(1)
04-21 13:57:55.938 W fidonext: peer: outgoing connection errorpeer_id=Some(PeerId("12D3KooWFUBp...fEX4"))
  error=Failed to negotiate transport protocol(s): [
    (/ip4/127.0.0.1/tcp/46351/p2p/...: Connection refused (os error 111)),
    (/ip4/10.0.2.15/tcp/46351/p2p/...: Connection refused (os error 111)),
    (/ip4/10.0.2.16/tcp/46351/p2p/...: No route to host (os error 113))
  ]
04-21 13:57:55.938 D fidonext: peer: no relay reservation available for fallback dialingtarget_peer_id=12D3KooWFUBp...fEX4
04-21 13:57:55.938 W fidonext: peer: blob fetch outbound request failedpeer=... request_id=OutboundRequestId(1) error=Failed to dial the requested peer
04-21 13:57:55.938 W fidonext: ffi: avatar fetch transport error Failed to dial the requested peer
04-21 13:57:55.938 D Libp2pService: fetchAvatar: peer_id=...fEX4 status=13
04-21 13:57:55.938 D ProfileSyncCoordinator: avatar transport miss ... attempt=1 nextInMs=5000
```

Same pattern repeats on attempts 2/3/4 at +6s / +22s / +53s. After attempt 4 (line 1660):

```
04-21 13:58:48.151 W ProfileSyncCoordinator: avatar transport-retry exhausted ... sha=f43586a1... (status=13)
```

Alice's side during the exact same window — **no inbound `/fidonext/blob-fetch/1.0.0` event at all**. She sees Bob in kademlia and tries to dial him back (e.g. for record replication), hitting the identical wall:

```
04-21 13:57:57.163 W fidonext: peer: outgoing connection errorpeer_id=Some(PeerId("12D3KooWSFJz...JpG"))
  error=[ /ip4/127.0.0.1/tcp/34103/...: Connection refused, /ip4/10.0.2.15/tcp/34103/...: Connection refused ]
04-21 13:57:57.163 D fidonext: peer: no relay reservation available for fallback dialingtarget_peer_id=12D3KooWSFJz...JpG
```

The DHT path itself works — Bob's `ProfileSyncCoordinator` successfully retrieved Alice's profile record (name, nickname, avatar sha256) via bootstrap replication. Only the request-response peer-to-peer dial fails.

## Hypothesis verdict

| # | Hypothesis | Evidence | Verdict |
|---|---|---|---|
| H1 | Alice never registers the blob | Phase 1 log `peer: self avatar stored; will serve on /fidonext/blob-fetch/1.0.0 avatar_sha256=f43586a1...` | REFUTED |
| H2 | Bob's request never reaches Alice | Bob dispatches 4, each fails `Failed to dial the requested peer`. Alice logcat shows zero inbound on `/fidonext/blob-fetch/1.0.0`. | **CONFIRMED (this is it).** |
| H3 | Alice receives, handler errors | No inbound ever observed. | Refuted by absence |
| H4 | Bytes returned but decoder fails | No bytes. | Refuted by absence |
| H5 | Protocol name mismatch v1 vs avatar-fetch | Both sides use `/fidonext/blob-fetch/1.0.0`; Alice provider log names it explicitly, Bob's request-response implicitly binds to it. | Refuted |

### Root cause (under H2)

Direct dial fails because both peers advertise only **LAN-only** listeners (`/ip4/127.0.0.1/...`, `/ip4/10.0.2.15/...`, `/ip4/10.0.2.16/...`) and those addresses are not routable across the two qemu emulator sandboxes. Libp2p's correct behaviour here is to fall back to a **relay circuit multiaddr** of the form `/ip4/217.65.5.134/tcp/41000/p2p/<relay>/p2p-circuit/p2p/<target>`. It does not — the core traces `no relay reservation available for fallback dialing` and the outbound fails.

Grepping all logcat captures from this run:
- `reserved` / `Reservation` / `cabi_node_reserve` — **0 hits** across Alice + Bob.
- `circuit` / `p2p-circuit` / `Dialed via relay` — **0 hits**.

Grepping the Android source tree (`fidonext_android/app/src/main`):
- `reserveRelay` / `reserve_relay` / `nativeReserveRelay` — **1 hit**, in `cpp/cabi-rust-libp2p.h:673` (the generated header declaration). No JNI export, no Kotlin caller.

Grepping libcabi: the symbol `cabi_node_reserve_relay` is exported (confirmed by `nm -gU`), so the plumbing exists on the Rust side, just never invoked.

This is a systemic transport issue, not avatar-specific. Avatar blob-fetch is the first feature to surface it because:
- Prekey, profile record, key-update: DHT-replicated through bootstrap peers, no peer-to-peer dial required.
- Encrypted messaging: currently traverses the mesh via bootstrap relays (per prior TD-03/TD-09 QA).
- Avatar blob fetch: `libp2p_request_response`, which *opens a fresh stream directly to the provider*. That's where transport reachability actually matters.

Consequently, the same bug will block TD-06 large-avatar / file transfer, TD-42 VoIP, and any future direct request-response / gossipsub-replies feature.

## Recommended fix owner + concrete code paths

Primary: **rust-p2p-engineer.** Secondary: **android-engineer** (only if option (b) below is chosen).

Two viable fixes, in order of preference:

### (a) Auto-reserve + circuit fallback in the core (preferred)

On bootstrap connection established, if the remote advertises `/libp2p/circuit/relay/0.2.0/hop`, issue a `client::Behaviour::reserve` automatically. Cache one or more successful reservations; then, in the request-response / outbound-dial path, when direct dial candidates fail, re-dial using a circuit multiaddr built from the cached reservations.

- File: `fidonext-core/c-abi-libp2p/src/peer/` (the swarm event loop). Search for the literal `"no relay reservation available for fallback dialing"` — that's the exact branch that needs to build a circuit address and re-dial instead of giving up.
- File: `fidonext-core/c-abi-libp2p/src/config.rs` — confirm the relay-client behaviour is in the swarm composition. If not, enable it alongside the existing `autonat` / `kad` / `request_response`.
- The existing `cabi_node_reserve_relay` becomes an optional manual trigger; not the primary mechanism.

### (b) Keep reserve explicit, add JNI + Kotlin wiring

If the core team prefers the app to decide when to reserve:

- File: `fidonext_android/app/src/main/cpp/libp2p_jni.cpp` — add `Java_com_fidonext_messenger_service_Libp2pService_nativeReserveRelay(env, clazz, handle, addr)` that forwards to `cabi_node_reserve_relay`. ~15 lines, mirrors the existing `nativeDial` binding.
- File: `fidonext_android/app/src/main/java/com/fidonext/messenger/service/Libp2pService.kt` — in `initNode()` after bootstrap connection success, iterate the two bootstrap peers and call `nativeReserveRelay(handle, bootstrapAddr)`. Expose a small AIDL method for future reuse.
- Core still needs the **circuit-fallback-in-dial** part from option (a); reservation alone is not enough if the request-response dispatcher never composes the circuit multiaddr.

Either way, without the circuit-fallback branch in the core's outbound dial path, option (b) alone does nothing visible to the user.

## Attribution / severity

- **Blame:** `rust-p2p-engineer` (missing circuit-fallback in the dial path; and, under option (a), missing auto-reserve logic).
- **Secondary:** `android-engineer` only if option (b).
- **Severity:** High. Avatars silently fail in production (no fatal, no UI error, just a blank circle). Also latent-blocker for TD-06, TD-42, TD-13.

## Artifacts

All logs + screenshots live under `/Users/vrembo/vrembo_prj/fidonext/fidonext_android/qa-artifacts/2026-04-21T1410Z-td30-diagnosis/`:
- `env.txt` — APK + libcabi sha256, peer IDs.
- `phase0-alice-raw.txt` — Alice cold-start full logcat.
- `alice-save.txt` + `alice-save-filtered.txt` — Phase 1.
- `bob-fetch.txt` + `bob-fetch-filtered.txt` + `bob-fetch-full.txt` — Phase 2 Bob side.
- `alice-handler-window-full.txt` + `alice-handler-window-filtered.txt` — Phase 2 Alice side (confirms no inbound).
- `alice-editprofile-before-save.png`, `bob-settings.png`, `bob-chatlist-after.png`.
