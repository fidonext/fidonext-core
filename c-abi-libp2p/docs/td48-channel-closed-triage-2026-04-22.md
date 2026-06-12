# TD-48 — peer-manager event loop dies silently when TD-47 flag is off

**Tracker**: NIM-90. Gate: v0.0.7 ship-gate6 on kunzite (QA
`qa-artifacts/2026-04-22T1440Z-ship-gate6/`).

## Symptom

With `cabi_transport_set_enable_relay_client(0)` called before
`cabi_node_new_with_seed` (TD-47 mitigation for the TD-46 multiaddr
SIGSEGV), the node boots, bootstrap dials succeed, the Kademlia
routing table populates, but every FFI call that goes through the
`PeerCommand` mpsc (`dht_put_record`, `dht_get_record`, `dial`,
`get_closest_peers`, …) returns
`peer manager command channel closed: channel closed` within ~430 ms
of `cabi_node_new`. 57 occurrences in a single 17-minute run.
`announceSelf` returns all-false, `publishProfileRecord` returns
`status=2` within 4 ms.

Reproduces 100% on kunzite. Appears NOT to reproduce on a06 — same
APK, same libcabi sha256 (`714fb6c2…9acc`), same amnezia-VPN
bootstrap list. Difference is the timing of the first
`SwarmEvent::ConnectionEstablished`.

## Root cause

`transport::libp2p::build_behaviour`, after TD-47 landed, does:

    let relay_client = if enable_relay_client {
        Toggle::from(Some(relay_client))
    } else {
        drop(relay_client);
        Toggle::from(None)
    };

That correctly dodges the TD-46 multiaddr deref-null because the
swarm's `handle_established_outbound_connection` no-ops on the
relay-client arm when `Toggle::from(None)` is installed. But the
relay **transport** half stays in the stack unconditionally, and
`peer::manager::PeerManager` — unaware of the flag — still invokes
`maybe_auto_reserve_relay` on `SwarmEvent::ConnectionEstablished`,
which calls `self.swarm.listen_on(…/p2p-circuit)` for each
configured bootstrap relay. `relay::client::new(peer_id)` binds the
Transport and Behaviour halves through a private mpsc that
`drop(relay_client)` severed, so the Transport's next poll on the
reservation path panics inside libp2p-relay's `priv_client`.

The panic unwinds `manager.run()`. The JoinHandle surface in
`ManagedNode::new` only matches the Err case

    if let Err(err) = manager.run().await {
        tracing::error!(target: "ffi", %err, "peer manager exited with error");
    }

which does NOT match `JoinError::Panic` — so we never emit the
"peer manager exited with error" trace, which is why earlier triage
thought the loop was still alive. Meanwhile other libp2p-internal
tasks (`libp2p_kad::handler`, TcpStream polling, etc.) keep running
on the same tokio runtime and keep logging — further obscuring the
real state. `self: PeerManager` is dropped when the task unwinds,
the `mpsc::Receiver<PeerCommand>` goes with it, and every subsequent
`handle.command_sender.send(...).await` returns `SendError`, which
the FFI layer renders as `peer manager command channel closed`.

### Why a06 appears to survive

On a06 (dual-stack cellular), `SwarmEvent::ConnectionEstablished`
fires ~2.5 s after `cabi_node_new` instead of the ~430 ms seen on
kunzite. In those 2 extra seconds, Android's `initializeNode` has
already completed its `Thread.sleep(500) → DHT write test →
announceSelf ×4` ladder. Those all go through `start_dht_put` in the
loop, finish successfully, and the DHT is "up" by the time the
crash window opens. After the crash, kunzite-style "channel closed"
errors DO start on a06 too — it just never looks broken to QA
because the visible KPI (`announceSelf`) is already green.

So a06 is NOT actually unaffected. The fix must apply everywhere.

## Fix (landed)

Thread `TransportConfig.enable_relay_client` into `PeerManager` as a
new `relay_client_enabled: bool` field. Use it to:

1. Early-return from `maybe_auto_reserve_relay` before any mutation
   (no `relay_reservation_attempted.insert`, no
   `start_relay_reservation` call).
2. Reject `PeerCommand::ReserveRelay` with a warn trace and a no-op
   `Ok(false)` so explicit reserve calls from the relay binary or
   future hosts don't regress the same way.

`try_dial_via_relay` naturally inherits the guard because it
early-returns when `relay_base_address.is_none()` — and with step 1
preventing us from ever calling `listen_on(/p2p-circuit)`, that
address is guaranteed to stay `None`.

Patches: BLOCK 1..5 in the TD-48 patch drop.

## Non-fix: do not remove relay-transport from the stack

TD-46/47 intentionally keeps the relay transport in the stack so
`/p2p-circuit` multiaddrs are still dialable as plain dials. We
preserve that — we only disable the **auto-reservation** code path
that calls `listen_on(…/p2p-circuit)` against a `Toggle<None>`
behaviour. Dialing an already-existing circuit (e.g. a cross-peer
address discovered via DHT) still works through the Transport's
dial side, which doesn't route through the dropped Behaviour.

## Regression test

`maybe_auto_reserve_relay_skips_when_relay_client_disabled` —
constructs a manager with `enable_relay_client=false`, primes a
bootstrap_relay_addrs entry, calls `maybe_auto_reserve_relay`,
asserts no state is mutated (`relay_reservation_attempted` empty,
`relay_base_address` None, `relay_peer_id` None). Lives next to
the existing auto-reserve tests in peer/manager.rs.

## Architect question — does this invalidate TD-47 approach?

**No.** TD-47's shape — disable the relay-client Behaviour half,
keep the Transport in the stack — is still correct. The bug is that
TD-47 didn't finish threading the flag into the one peer-manager
code path that dispatches work into the Behaviour half. The fix is a
~30-line guard in `peer/manager.rs`, not an architectural rethink.
TD-47 stays in v0.0.7.

## v0.0.8 follow-ups (not blocking)

- Audit all other `self.swarm.*` call sites in `peer/manager.rs` for
  hidden relay-client dependencies so we don't repeat this
  discovery once we add DCUtR (TD-13) or any other relay-dependent
  feature.
- Capture `JoinError::Panic` on the worker `JoinHandle` inside
  `ManagedNode` so the next unwind is logged instantly. Separate
  NIM ticket worthwhile.
