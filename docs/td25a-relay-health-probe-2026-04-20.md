# TD-25 — relay fleet health probe (QA #5 regression triage, 2026-04-20)

**Date:** 2026-04-20 / 2026-04-21 UTC
**Triaged by:** `devops-relay`
**Verdict:** **fleet-explains-regression** — the "mesh" is not a mesh. Relay-02 has accepted **zero** DHT records over 3 days of uptime; all profile/prekey/directory records live on relay-01 only. Any Kademlia `get_record` whose XOR distance to the key lands closer to relay-02 (or to a transient mobile-client K-bucket entry) will TIMEOUT because there is no replica to serve it. Additionally, relay-01's routing table is heavily polluted with unroutable mobile-client addresses (RFC-1918 / emulator NAT) which further slow `get_record` by forcing 110-second TCP-connect timeouts during K-bucket refresh.

## 1. Scope

QA evidence under review:
- `fidonext_android/qa-artifacts/2026-04-20T2218Z-td2122-rewired/` (QA #5, FAIL).
- Reported last-good baseline: QA #3 at 2026-04-20T20:21Z (7 successful fetchProfileRecord in ~30–45 s).
- QA #5 at 2026-04-20T22:18Z–22:53Z: Bob's `fetchProfileRecord` returned `status=6 TIMEOUT` on 7 attempts; Alice's `publishProfileRecord` claimed `status=0` twice (pre- and post-force-stop re-publish).

Fleet: single VPS `217.65.5.134` (inventory entry `relay-01`). On that host: two docker containers `fidonext-relay` (TCP/41000, peer_id `12D3KooWPmi5…TyuF`) and `fidonext-relay-02` (TCP/41001, peer_id `12D3KooWHrer…YY8S`). **Relay-02 is NOT in `relay-inventory.json`** — inventory drift since TD-02 resolution. A third mesh peer `12D3KooWSAPj…T1ag @ /ip4/89.167.55.118/tcp/41000` appears in both relays' logs as an already-connected peer at startup.

Constraints honoured: no restarts, no redeploys, no bootstrap-line changes, no writes to the VPS beyond read-only log greps.

## 2. Host-level health (baseline green)

Probed 2026-04-20 23:07Z.

- `docker ps`: both containers `Up 3 days`, restart count **0**, `OOMKilled: false`, started 2026-04-17T19:57 / 21:05 UTC.
- `uptime`: 3d 4h, load average `0.17 / 0.16 / 0.17` on a 2-core box.
- `free -m`: 846M used / 3068M available; 20M of 974M swap in use.
- `df -h /`: 12G used / 97G total — 13% full. No pressure.
- Firewall `ufw`: `22/tcp`, `41000/tcp`, `41001/tcp` open. No QUIC UDP open (correct per `use_quic: false`).
- `ss -ltnp`: both ports LISTEN via `docker-proxy`.
- External probe `nc -vz 217.65.5.134 41000` and `:41001` — both succeeded. Ports reachable from the public internet.

No drift, no churn, no restart since TD-02 bring-up. The plumbing is fine.

## 3. Protocol-level findings

### 3.1 The "mesh" is effectively a single replica

Over 3 days of logs:

| Relay | `Record stored` events | 209-byte profile records | Non-test records |
|---|---|---|---|
| relay-01 (41000) | **787** | 4 (all between 21:51Z–22:07Z, Alice only) | ~95 |
| relay-02 (41001) | **0** | 0 | 0 |

Relay-02 only issued `started dht put_record` / `get_record` **twice** in 3 days (both at its own startup at 19:58:01Z on 2026-04-17), and its own initial `put_record` timed out with `WARN dht put_record timed out, stored record locally as fallback` (visible in its startup log, line 30).

This means: **Kademlia replication is not happening between the two relays.** In a libp2p-kad DHT with the default `REPLICATION_FACTOR=20`, `put_record` stores to the K closest peers by XOR distance. With only 3 super-peers in the swarm (≪ K), every peer should be a replica for every key. The fact that relay-02 holds zero records indicates that clients' `put_record` quorum-1 path is short-circuiting at the first successful store (the relay-01 node itself, which is always reachable) and never fanning out to replicas. This matches the Rust `e2ee/*` client API which uses `Quorum::One` for writes — write succeeds as soon as the originating node itself stores, regardless of how many other replicas accept.

Consequence: **a `get_record` query from Bob can fail whenever Kademlia routes it to relay-02 (or to any of the polluted routing-table entries — see §3.2) instead of to relay-01.** The routing decision is per-key: XOR(query_key, peer_id). Alice's peer_id rotates across test runs (TD-20), so each run hashes to a different position in the DHT ring, and some keys happen to land closer to relay-02 than to relay-01.

### 3.2 Kademlia routing table is polluted with unroutable client addresses

Sample `outgoing connection error` counts from relay-01 in the last 1 h before probe (2026-04-20 22:07–23:07Z):

```
344  /ip4/82.26.93.14        (residential ISP, 16+ stale ephemeral ports, all TimedOut)
 85  /ip4/10.0.2.15          (Android emulator NAT local — unroutable from public)
 23  /ip4/10.0.2.16          (Android emulator NAT local — unroutable from public)
  5  /ip4/127.0.0.1          (loopback — only self)
  1  /ip4/192.168.1.196      (LAN)
  1  /ip4/10.241.58.31       (RFC-1918)
```

459 TCP-connect timeouts in one hour. Each timeout is `os error 110 / Connection timed out`, which on Linux default TCP-SYN retries is a **~110 s** wall-clock block per unreachable address. When `Swarm::poll` probes a K-bucket entry during Kademlia maintenance or during a `get_record` traversal, it sits on these 110 s timeouts one address at a time (e.g. line 83 of `relay01_startup_and_errors.log` shows a single 16-address burst for one peer — up to 16×110s = ~29 min of wall-clock "stuck" per peer, though libp2p does parallelise).

`added address to kademlia peer_id=12D3Koo… address=/ip4/10.0.2.15/… source="identify"` entries appear throughout the logs. The relay is trusting the `identify` protocol output from mobile clients and inserting their self-reported LAN addresses into the routing table. These never become reachable from the VPS.

Secondary symptom: relay-01's own Kademlia bootstrap query times out repeatedly. 562 `Bootstrap(Err(Timeout { peer: 12D3KooWPmi5…TyuF }))` events in the last hour — debug-level, non-fatal, but indicative of how degraded the routing table is.

### 3.3 Bob's get_record window analysis

Records stored on relay-01 around the QA #5 window (all UTC):

```
22:30:03Z  prekey/v1/peer/…SuBSB…       (client B peer)
22:30:15Z  prekey/v1/account/…Gux5…     (Alice account)
22:33:09Z  directory/v1/account/…NTwA…  (Bob account)
22:33:21Z  prekey/v1/peer/…FCcg…        (Bob peer)
22:33:31Z  prekey/v1/account/…NTwA…     (Bob account)
22:40:27Z  directory/v1/peer/…SuBSB…    (last non-test record)
-- 68-minute gap; only QA synthetic `fidonext/test/…` stores resume at 23:49Z --
```

Alice's profile-record re-publish at `22:42:07Z` (from QA log) left **zero** `Record stored: 209 bytes` event on either relay. Two plausible interpretations:

1. Alice's `publishProfileRecord` `status=0` reflects only her own local Kademlia `put_record` accepting the record locally with quorum=1 (she herself is in the K-closest set), but the record never propagated to a relay replica. This is consistent with the single-replica topology in §3.1.
2. Alice's stream to the relay was backpressured/dropped at that moment — nothing in logs corroborates an explicit drop, so (1) is more likely.

Bob's 7 `fetchProfileRecord` attempts (22:18Z–22:53Z) then traverse a Kademlia query targeting `SHA-256("fidonext/profile/v1/" || alice_peer_id)`. Given:
- Only relay-01 has ever stored ANY profile record.
- Alice's latest (re-published) profile for this peer_id never made it to a relay.
- Bob's Kademlia must cross polluted K-buckets full of 110-s-timeout addresses.

The `status=6 TIMEOUT` outcome is the expected consequence of this fleet shape, independent of any libcabi change between QA #3 and QA #5.

### 3.4 Why QA #3 "worked"

QA #3 records from relay-01 at 20:20–20:33Z show a full fresh write set (directory + prekey + profile 209-byte record at 21:51/21:57/22:00/22:07 — actually the profile was stored slightly later, in the lead-up to QA #5 but BEFORE Alice's post-force-stop re-publish). So at the time Bob ran fetchProfileRecord in QA #3, the relevant profile record WAS present on relay-01, and Bob's XOR-routing happened to hit relay-01. In QA #5, Alice's identity rotated (TD-20 identity churn on `am force-stop`), the key moved in the ring, and Bob's lookups landed on the empty replica. The fleet did not change state between the two runs; the **key-to-replica mapping** did.

### 3.5 Bootstrap configuration is asymmetric

- relay-01's startup cmdline bootstraps to relay-02 (`/ip4/217.65.5.134/tcp/41001/p2p/12D3KooWHrer…YY8S`) — OK.
- relay-02's startup cmdline bootstraps to relay-01 (`/ip4/217.65.5.134/tcp/41000/p2p/12D3KooWPmi5…TyuF`) — OK.
- Both then dial a third peer `12D3KooWSAPj…T1ag @ 89.167.55.118/tcp/41000`. That IP is NOT a known fleet relay (inventory only lists `217.65.5.134`). It is either a leftover bootstrap from the cloud-init, an external community node, or a developer laptop. Not a blocker, but noteworthy — it means the DHT has an off-inventory member.

### 3.6 TD-01 still in effect

Both containers run `python3 /app/ping_standalone_nodes.py --role relay --force-hop …`. The relay image is still the Python example, not a Rust binary. This is known tech debt (TD-01) and is not the cause of the TD-25 regression, but it limits what we can do on the relay side — e.g. we cannot easily tune Kademlia parameters (replication factor, `addresses_of_peer` policy, identify-address filtering) without first shipping a proper Rust relay.

## 4. Verdict

**fleet-explains-regression.** The QA #5 timeout is fully accounted for by:

1. No cross-relay replication. Records live only on relay-01.
2. Alice's post-force-stop re-publish did not land on any relay (most likely because local-quorum-1 accepted it before propagation).
3. Routing-table pollution inflates `get_record` tail latency beyond the client-side timeout window.

QA #3 succeeded by luck of key placement; QA #5 failed by unluck of key placement combined with a re-publish that stayed local. No libcabi regression is required to explain the observation.

## 5. What I did NOT change (per constraints)

- No restarts. Both containers still `Up 3 days` as of probe end.
- No redeploys.
- No bootstrap-line changes.
- No writes to `/opt/fidonext-relay/`.
- No inventory `relay-01` field updates (status is still accurate: `live`).

## 6. Recommended follow-ups (separate tickets, needs PO sign-off)

Proposed for rust-p2p-engineer + devops-relay jointly (flagging here, not executing):

1. **Replication**: client-side `publish_record` should use `Quorum::Majority` or explicit `put_to` routing to pin at least 2 relay replicas. Alternative: run the `kad-provider-record-refresh` background job on both relays so they pull each other's records.
2. **Identify filter**: in the relay (when we build the Rust binary — TD-01), filter `identify` reported addresses so RFC-1918 / loopback / link-local / Android-emulator `10.0.2.0/24` are NOT added to the Kademlia routing table. Libp2p provides `identify::Config::with_public_addresses_only(true)`-style knobs; verify.
3. **Relay bootstrap list in clients**: when bootstrap contains two relays on the same host, they share fate for network partitions and do not provide real replication. Add a real second host before prod.
4. **Inventory drift**: add a `relay-02` entry pointing at TCP/41001 with the observed peer_id, and document the off-inventory third peer `12D3KooWSAPj…T1ag @ 89.167.55.118/tcp/41000` (is this ours, or external?). I did not edit `relay-inventory.json` in this probe.
5. **TD-01**: replace the python-example runtime with a proper Rust bin before the first production host. TD-25 intersects with TD-01 because a Rust relay can publish health metrics (peer count, record count, routing-table quality) that would have surfaced this single-replica topology weeks ago.

## 7. What would change the verdict

If evidence emerges that a `fidonext/profile/v1/...` `get_record` query completed successfully on relay-01 during QA #5 but still returned TIMEOUT to the client (e.g. an Android-side IPC / FFI hang), the fleet story becomes partial. Would need:

- Tracing of a specific `get_record` QueryId from relay-01 during 22:42–22:53Z, matched against Bob's logcat QueryId or the FFI callback timestamps.
- Confirmation of whether Alice's `publishProfileRecord` call path actually sends an `ADD_PROVIDER` / `PUT_VALUE` to the relay (network-level capture) vs. short-circuits locally.

These are orthogonal to the present probe; I would ask `rust-p2p-engineer` to wire a `QueryId`-tagged event stream through the FFI before QA re-runs.

## 8. Artifacts

Raw grep outputs used to derive this report are under `.triage-td25/` (repo-local, not committed):

- `relay01_last500.log`, `relay02_last400.log` — recent log tails.
- `relay01_startup_and_errors.log`, `relay02_startup_and_errors.log` — startup + WARN/error grep.
- `nontest_records.log` — non-test record stores 20:00Z–23:15Z.
- `late_window.log` — QA #5 window record activity.
- `profile_records.log` — 209-byte profile-record stores across all time.
- `counts_overview.log` — totals (787 vs 0).
- `window_analysis.log` — unroutable-address counts.

These contain client peer_ids (which are public identifiers by design) but no secrets. Not committed to git.
