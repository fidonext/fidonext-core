# Upstream issue draft — rust-libp2p

**Target repo:** https://github.com/libp2p/rust-libp2p/issues/new
**Ready to file via:** web UI (paste body below) OR `gh issue create -R libp2p/rust-libp2p --title "<title>" --body-file <this file excluding the preamble>`

**Updated 2026-04-22** with 3rd backtrace (SIGBUS during Connection drop) observed in ship-gate7 after applying our own local mitigations for the first two.

---

## Title

`Three distinct libp2p-relay crashes on arm64 Android under amnezia VPN (0.56.0 / swarm 0.47.1 / relay 0.21.1) — reproducible`

---

## Body

### Summary

On Android `arm64-v8a` with an active VPN (tested with amnezia VPN, `tun0`/`tun1` MTU 1376), the libp2p-relay client crate reliably hits **three distinct crashes** on the same reproducer device (a Xiaomi POCO running Android 14). A second device on the same app build, same bootstrap list, without a VPN is healthy for all three. This is not one bug — it is three different code paths inside `libp2p-relay` that misbehave when the underlying transport is VPN-wrapped. We have ruled out device-local memory corruption: the same APK on a different arm64 Android device (Samsung A06) with the same amnezia VPN does not reproduce *any* of the three.

### Environment

- Host: Android 14 on `aarch64` (`arm64-v8a`), two real devices, one reproduces deterministically.
- Reproducer device: Xiaomi POCO (kunzite), amnezia VPN active throughout, `tun0` UP with default route, MTU 1376.
- Healthy device: Samsung A06, amnezia VPN active on `tun1`, same MTU 1376 — but apparently different kernel packet-handling timing that masks the crashes.
- Rust toolchain: stable, Android NDK 27.0.12077973 target `aarch64-linux-android`.
- Crate versions (from `Cargo.lock`):
  - `libp2p 0.56.0`
  - `libp2p-core 0.43.2`
  - `libp2p-swarm 0.47.1`
  - `libp2p-relay 0.21.1`
  - `libp2p-identify 0.47.0`
  - `libp2p-kad 0.48.0`
  - `libp2p-autonat 0.15.0`
  - `multiaddr 0.18.2`
- Swarm composition (`NetworkBehaviour` derive): identify + autonat + kademlia + relay-client + relay-server(Toggle) + gossipsub + rendezvous + a few project-local request-response behaviours.

### Crash #1 — NULL-deref in `multiaddr::Protocol::from_bytes` at connection establishment

**When:** During `handle_established_outbound_connection` on the *first* relay-bootstrap connection (or a later DHT-discovered peer with a similar multiaddr shape).

**Symbolicated backtrace:**

```
#00 multiaddr::protocol::Protocol::from_bytes      (x0 = 0, NULL slice data_ptr)
#01 <multiaddr::Iter as Iterator>::next
#02 <Multiaddr as MultiaddrExt>::is_relayed        (libp2p_relay::multiaddr_ext)
#03 libp2p_relay::priv_client::Behaviour::handle_established_outbound_connection
#04 <our NetworkBehaviour>::handle_established_outbound_connection (derive)
#05 libp2p_swarm::Swarm::poll_next_event
```

Reaching `from_bytes` with `x0 = NULL` implies the iterator is holding a `&[u8]` whose data pointer is null while `len > 0`. Every public `Multiaddr` constructor validates bytes and stores them in `Arc<Vec<u8>>` — safe Rust cannot produce this state. Strongly suggests heap corruption / UAF of the `Arc<Vec<u8>>` backing a `Multiaddr` held somewhere along the relay-client dial path.

### Crash #2 — panic on reservation `listen_on` after dropping client Behaviour

**When:** We tried to mitigate Crash #1 by omitting `relay::client::Behaviour` from the composite (replacing it with `Toggle::from(None)`). `relay::client::new()` was still called and the Transport half retained in the stack, the Behaviour half dropped. On the first `SwarmEvent::ConnectionEstablished` for a bootstrap relay, our code called `self.swarm.listen_on(<relay>/p2p-circuit)` — which panicked inside libp2p-relay's `priv_client` Transport on the next poll because the Transport↔Behaviour private mpsc created by `relay::client::new()` had been severed by the `drop(relay_client)`.

The panic unwinds the manager task. If the enclosing `.await` only matches `Result::Err` (as ours did), `JoinError::Panic` is silently swallowed and all downstream observers see "sends to mpsc return ChannelClosed" rather than the real cause. This is a subtle footgun: the public contract should either (a) document that `listen_on(/p2p-circuit)` requires the Behaviour half to be present, or (b) degrade gracefully (return `ListenerError` instead of panicking) when it isn't.

We patched our side by never calling `listen_on` when the Behaviour is absent. Would prefer the Transport-level graceful failure in upstream.

### Crash #3 — SIGBUS/BUS_ADRALN in `priv_client::handler::Handler` drop path

**When:** With Crashes #1 and #2 mitigated on our side (relay-client Behaviour composed as `Toggle::from(None)`, no `listen_on(/p2p-circuit)` ever issued), the **Handler tower** still contains `ToggleConnectionHandler<Either<libp2p_relay::priv_client::handler::Handler, Dummy>>` as part of every Connection's handler stack. During routine bootstrap cycling (~4 min into a 10-min burn-in), a Connection drops and `drop_in_place` walks the full handler tower. On arm64 we hit **SIGBUS / BUS_ADRALN** at a 7-byte-misaligned fault address inside `priv_client::handler::Handler` state.

**Symbolicated backtrace:**

```
SIGBUS / BUS_ADRALN / fault addr 0x7013ee574f (7-byte misaligned)
#00 core::ptr::drop_in_place::<libp2p_identify::handler::Handler>
#01 drop_in_place::<ConnectionHandlerSelect<kad+ping, identify, autonat>>
#02 drop_in_place::<ConnectionHandlerSelect<..., gossipsub,
                     ToggleConnectionHandler<Either<libp2p_relay::priv_client::handler::Handler, Dummy>>,
                     ToggleConnectionHandler<Either<libp2p_relay::behaviour::handler::Handler, Dummy>>>>
#03 drop_in_place::<ConnectionHandlerSelect<..., rendezvous, DeliveryDirect req/resp>>
#04 drop_in_place::<libp2p_swarm::connection::Connection<...>>
#05 <tracing::instrument::Instrumented<T> as Future>::poll
#06 tokio::runtime::task::core::Core::poll
```

Looks like a field layout / alignment bug in `priv_client::handler::Handler` on arm64, only exposed when the `Dummy` alternative is *not* active (i.e. the normal "client is enabled" case). Or possibly a field initialised via unchecked `MaybeUninit` pattern that's valid on x86_64 but UB on arm64.

### Does not reproduce without VPN, and does not reproduce on the second arm64 device

- Xiaomi POCO (kunzite) + amnezia VPN: 100% reproduction rate, deterministic timing.
- Samsung A06 + amnezia VPN: none of the three crashes reproduce in the same burn-in window. The A06 is *slower* on first-connection establishment, which appears to change timing enough to mask all three.
- Either device without a VPN: healthy.

### What we tried locally (didn't fix any of them)

1. **`libp2p-swarm 0.47.0 → 0.47.1` + `libp2p-relay 0.21.0 → 0.21.1`** (chasing the PR #6138 hashlink LRU swap, hoping Crash #1 was UAF in the peer-address cache). Cargo.lock patch only, no source change. **Crash #1 still reproduces**, zero frames in `lru`/`hashlink` on the stack.
2. **Swapping relay-client `Behaviour` to `Toggle::from(None)`** to dodge Crash #1 at establishment. Works — Crash #1 never fires — but exposes Crash #2 (panic on `listen_on`), which we then worked around by never issuing the reservation when the Behaviour is absent, which then exposes Crash #3 (SIGBUS on Connection drop).
3. **Defensive `Toggle<None>` for the entire Handler tower** — not tried yet; would require constructor-time exclusion of the whole `libp2p-relay` client integration rather than a runtime toggle. If upstream acknowledges the Handler-layer bug we'd prefer a proper fix there.

### Reproducer / artifacts

Happy to share:
- Full logcat from both devices (~14 MB) with `F/libc` + `F/DEBUG` tombstones for all three crashes.
- Symbolicated backtraces (generated with `llvm-addr2line` against the exact shipped `libcabi_rust_libp2p.so`).
- The exact swarm composition in our `NetworkBehaviour` derive (non-trivial but not secret).
- A minimal reproducer (our swarm stripped to just identify + autonat + kademlia + relay-client over TCP) if useful.

### Hypothesis (educated guess, may be off)

Crashes #1 and #3 both touch heap/pointer integrity in `priv_client::handler::Handler` or neighbouring types. Crash #2 is clearly a "precondition violation" issue that upstream can harden into a graceful failure. We suspect all three may share a root cause around how `priv_client::Handler`'s state is initialised or dropped when the underlying stream behaves in a way the handler doesn't expect (the amnezia-VPN-shaped packet timing / MTU seems to be the trigger). An `unchecked_alignment` or `MaybeUninit::assume_init` somewhere in that path would explain arm64-only manifestation.

### What we're doing on our side

- Shipping v0.0.7 with a runtime `TransportConfig.enable_relay_client` flag; when Android detects a VPN, we flip it off, which composes the Behaviour as `Toggle<None>`. This dodges Crashes #1 and #2 entirely.
- For Crash #3 we are still exposed on the Handler drop path. v0.0.8 plan is to do a constructor-time exclusion of the `libp2p-relay` client integration (two NetworkBehaviour types, picked at init) so the Handler never enters the tower — unless upstream lands a fix for Crash #3 first, in which case we'd happily remove our workaround entirely.

### Tags

`bug`, `help wanted`, `libp2p-relay`, `multiaddr`, `platform:android`, `arm64`.

---

## Preflight checks before filing

- [ ] Search open issues for "is_relayed" / "Protocol::from_bytes" / "multiaddr null" / "SIGSEGV relay" / "SIGBUS relay handler" — if a match exists, comment there instead of opening a new one.
- [ ] Confirm which GH account files (vrembo personal vs fidonext bot).
- [ ] If filing via `gh`, install and auth first: `brew install gh && gh auth login`.
- [ ] Strip any sensitive fields from attached logcat before uploading (peer_ids are public, but IP addresses / VPN endpoints should be masked).
- [ ] Link the crash-1 and crash-3 tombstones + symbolicated backtraces (attach as files, not inline — they're ~3-8 MB).
