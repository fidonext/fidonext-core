# TD-25b — DHT regression audit, 2026-04-20

Scope: code review only. Compare QA #3 libcabi (`e924225`-era, sha `41db590a…`) vs QA #5 libcabi (`1fdf05f`-era, sha `d130d85c…`). Between those two runs Bob's `cabi_e2ee_fetch_profile_record` went from succeeding in 30-45 s (QA #3) to persistently returning `status=6` (timeout) over 35 min (QA #5), even after Alice explicitly re-published.

The only fidonext-core commits between the two sha's are `e924225`, `8878680`, `1fdf05f`.

## Verdict

**`no-regression-found`** in the three libcabi commits under review. Hand off to `devops-relay` as the primary suspect for TD-25b.

If devops-relay clears the fleet, fall back to `inconclusive-need-repro` and request a repro with `RUST_LOG=peer=trace,libp2p_kad=debug` on both Alice and Bob so we can see whether the `get_record` round is even *starting* (do we see `started dht get_record query`?), whether Kademlia has any peers in the routing table when the query starts, and whether the timeout is the 15 s Kademlia `query_timeout` (fast) or the Android-side FFI timeout (slow). That single log line is the difference between "routing table empty" and "routing table fine but no reachable replica".

## Per-commit behavioural diff (DHT surface only)

### `e924225` — TD-18 periodic re-announce + query_timeout 5 s → 15 s

Files: `peer/manager.rs`, `lib.rs`, `transport/libp2p.rs`.

New behaviour:

1. `PROFILE_REANNOUNCE_INTERVAL = 10 min` timer wired into `PeerManager::run()` via `tokio::time::interval_at(Instant::now() + PROFILE_REANNOUNCE_INTERVAL, …)`. **First tick fires 10 min after start, not at 0 min.** No-op until the host has called `cabi_e2ee_publish_profile_record` at least once and thereby populated `self_profile_record_{key,bytes,ttl_seconds}`.
2. New `PeerCommand::PutProfileRecord` variant. Functionally identical to `PutDhtRecord`, except it also caches `(key, bytes, ttl)` **before** calling `start_dht_put`. Caching is unconditional of the put outcome (so a failed put still gets retried on the next tick).
3. `start_dht_put()` factored out of the existing `PutDhtRecord` handler. Same `kad::Quorum::One`, same `publisher = Some(local_peer_id)`, same `NoKnownPeers` local-store fallback. The only new code path is `response: Option<…>` — when `None` (the periodic tick) the helper does **not** insert into `dht_put_queries`, so completion events for tick-puts land in `handle_put_record_result` and are dropped via the pre-existing `let Some(pending) = … else { return }` guard at `peer/manager.rs:2466`. No query-id collision, no map leak.
4. `cabi_e2ee_publish_profile_record` routes through the new `dht_put_profile_record` method instead of `dht_put_record`. The FFI signature and effective DHT semantics are identical from the caller's POV (`Ok(())` on quorum or on fallback, same `DhtQueryError` mapping).
5. `kad_config.set_query_timeout(5) → set_query_timeout(15)` in `transport/libp2p.rs:300`. This loosens, never tightens, the fetch-side timeout. On the sparse test fleet this should **help** `get_record` succeed, not regress.

The fetch path (`cabi_e2ee_fetch_profile_record` → `dht_get_record` → `PeerCommand::GetDhtRecord` → `handle_get_record_result`) is byte-for-byte unchanged (verified by diffing `6d1fe62:peer/manager.rs` against current: `handle_get_record_result` body is identical).

### `8878680` — TD-20(b) randomize temp path + `create_new` guard

File: `e2ee/mod.rs` only. Strictly local filesystem. Zero DHT interaction. `persist_profile` is only reached from `create_profile`, which is gated by `!path.exists()` in `load_or_create_profile`, so it is called at most once per cold-start. The `hard_link` choice here is the SELinux blocker that TD-23 fixes — but in the QA #5 timeline, `hard_link` was already reverted, so this commit's DHT impact is nil.

### `1fdf05f` — TD-23 swap `hard_link + remove` for `rename`

File: `e2ee/mod.rs` only. Strictly local filesystem. Zero DHT interaction. Fixes Android SELinux denying `link`; without this fix the Android binding returns `nodeHandle=0` at cold start (so the node never reaches the point of publishing or fetching anything). In QA #5 the node is alive, publishing, and fetching (it's getting `status=6`, not nil-node), so this commit is also *necessary* for QA #5 to even run — it did not introduce the fetch timeout.

## Cross-cutting checks

- **Command-channel starvation / mutex ordering.** `tokio::select!` over `command_receiver`, `delivery_tick` (1 s), `profile_reannounce_tick` (10 min), `swarm`. Each branch is non-blocking; `handle_profile_reannounce_tick` fires one non-blocking `swarm.behaviour_mut().kademlia.put_record()` and returns. 10-min cadence can't starve 1 s delivery or sub-second `get_record` completion events. A tick arriving mid-`get_record` cannot cancel the pending `dht_get_queries[query_id]` entry — the two maps (`dht_put_queries`, `dht_get_queries`) are disjoint.
- **Record-format compatibility across sha's.** `e2ee/profile_record.rs` is last touched at `dbfc7d6` (TD-06 avatar rename, pre-dates both QA sha's). Canonical CBOR encoding + domain-sep signing string (`b"fidonext-profile-record-v1\x00"`) is frozen. A record signed by QA-#3-era libcabi validates identically under QA-#5-era libcabi.
- **`publisher` field on re-announce.** `start_dht_put` always sets `publisher = Some(self.local_peer_id.clone())`. Alice's cached bytes are re-submitted under a fresh `kad::Record` with her current `local_peer_id` as publisher, which is the same value every time. No drift.
- **FFI timeout wiring.** `ManagedNode::dht_get_record` is `runtime.block_on(handle.dht_get_record(key))` with no explicit FFI-side deadline. The timeout that the Android binding observes as `status=6` is whatever Kademlia reports back via `DhtQueryError::Timeout`. With TD-18 the Kademlia `query_timeout` is 15 s; so if `status=6` is landing in ~15 s on Bob, TD-18 is working as intended — the timeout is Kademlia concluding there is no reachable replica. If `status=6` is landing in ~30-60 s instead, the fetch is likely hitting an Android-side watchdog on top of a Kademlia query that never completes (routing table empty / relay-mediated DHT traffic blocked).

## Why I think this is a fleet issue, not a code issue

Everything TD-18 changes is **additive and opt-in**:
- Re-announce tick is a no-op until `publish_profile_record` is called.
- `start_dht_put` refactor preserves the exact pre-existing path for `PutDhtRecord`.
- `query_timeout` only grows.

And everything TD-20(b)/TD-23 changes is strictly local filesystem. There is no code path in these three commits that **reduces** the reachability of a DHT record from Alice to Bob. If Alice is successfully publishing (she returns `status=0` from `cabi_e2ee_publish_profile_record`, implying either a Kademlia `put_record` quorum OR the local-store fallback fired because she had **no peers** at put time), and Bob is timing out at `get_record`, the most parsimonious explanations are:

1. Alice's put fell through to the local-store fallback because her own routing table was empty/near-empty, so the record was never replicated to any relay. The TD-18 re-announce only helps if Alice has peers at *some* tick — if she is relay-isolated for the whole session the re-announce keeps re-falling into the local store.
2. Bob's routing table does not reach any node that has Alice's record. On a two-relay fleet this means the relays themselves aren't serving as Kademlia replicas for the profile key, or are dropping `get_record` requests.

Both are relay-fleet / routing-table issues, not core-code issues.

## Proposed follow-ups (not patches)

- Repro with `RUST_LOG=peer=info,libp2p_kad=debug` on both Alice and Bob. Look for `started dht put_record query` on Alice and `started dht get_record query` on Bob, plus the Kademlia routing-table peer count at each point. If Alice never logs `started dht put_record query` (only the `NoKnownPeers` fallback `stored record locally as fallback` warn), the record was never replicated and TD-18 can't save us — Alice is isolated.
- Consider adding a `cabi_dht_routing_table_size()` FFI peek so the Android binding can surface `"isolated — 0 peers in DHT routing table"` to the user instead of silently timing out. (Out of scope for TD-25b; flagging for roadmap.)
- If devops-relay confirms the fleet is healthy, escalate to `security-crypto-engineer` for a second look at whether the signed record blob validates identically across the two sha's — but I consider this a near-zero risk given `profile_record.rs` is unchanged.
