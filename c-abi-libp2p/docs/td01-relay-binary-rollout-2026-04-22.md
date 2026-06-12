# TD-01 — relay binary rollout across the test fleet (2026-04-21/22)

**Date:** 2026-04-21 UTC (crossing into 2026-04-22)
**Operator:** `devops-relay`
**Source commit:** `8ad0fbb` "TD-01: proper Rust relay binary with gossipsub topic subscribe" (local on dev laptop, not pushed to origin).
**Verdict:** **LIVE on all 3 hosts.** Python-wrapper runtime retired. Every relay now subscribes to `/fidonext/nickname-registry/v1` at startup. PeerIds unchanged across the upgrade. Client-side reciprocal gossipsub subscribe confirmed from a laptop-run `fidonext-relay` binary.

## 1. Payload recap

Commit `8ad0fbb` replaces:

- `c-abi-libp2p/deploy/relay/Dockerfile` → builds `cargo --bin fidonext-relay` and runs it directly on `debian:bookworm-slim`. No Python, no FFI, no cdylib in the runtime stage.
- `c-abi-libp2p/deploy/relay/entrypoint.sh` → translates env-vars (`LISTEN_ADDR`, `FORCE_HOP`, `USE_QUIC`, `BOOTSTRAP_PEERS`, `SUBSCRIBE_TOPICS`, `EXTRA_ARGS`) into clap flags and execs the native binary.
- `c-abi-libp2p/src/bin/fidonext_relay.rs` → new binary target with clap CLI. Default subscribes to `["/fidonext/nickname-registry/v1"]` plus the built-in `echo` topic (inherited from `PeerManager`).

Motivation: the Python-wrapper image never joined the application-level gossipsub mesh. `qa-artifacts/2026-04-21T2107Z-td42-shipgate-retry/` (PO's blocker for v0.0.7) showed `NoPeersSubscribedToTopic` whenever a publisher and subscriber landed on different relays. Native binary + default topic list fixes that.

## 2. Rollout order and sequencing

1. **relay-03** (`217.65.5.241:41000`, separate VPS) — blast-radius minimal; goes first.
2. **relay-01** (`217.65.5.134:41000`, shared kunzite VPS).
3. **relay-02** (`217.65.5.134:41001`, same VPS as relay-01).

The TD-01 image is tagged `fidonext-relay:local` on each host. On the shared kunzite VPS, one `docker build` produces the image that both relay-01 and relay-02 consume. Recreating each container sequentially keeps at least one relay live throughout the rollout.

## 3. Per-host timeline

### 3.1 relay-03 — first upgrade

- **Pre-upgrade state (21:35Z probe):** container `fidonext-relay-03` Up 6 h on `fidonext-relay:local` (Python wrapper from `ee36285`, TD-36 bring-up). PeerId `12D3KooWHq7BXHFUP75JKZUwqNozsNyEXyTjrmjPjUKt8RDeJcTV`.
- **Source transfer:** `apt install rsync` on the host, then `rsync -az --delete --exclude target/ --exclude .git/ --exclude '*.so' --exclude docs/ c-abi-libp2p/ → /opt/fidonext-relay/src/c-abi-libp2p/`. Layout preserved — the TD-36 compose already points `context: ./src` at `c-abi-libp2p/deploy/relay/Dockerfile`.
- **Build:** `docker compose build relay` → `Finished 'release' profile [optimized] target(s) in 6m 35s`. Full wall clock **405 s** (6 min 45 s). Image sha `91c07a42638c…`.
- **First boot (crash-loop, caught and fixed):** the old `.env` from TD-36 contained `USE_QUIC=0` and `USE_WS=0`. The new clap CLI parses `USE_QUIC` via `#[arg(env = "USE_QUIC")]` and rejects `0` with `invalid value '0' for '--use-quic'`. Container restart-looped 5 times in ~15 s before I noticed.
  - Fix: `sed -i 's/^USE_QUIC=.*/USE_QUIC=false/' .env; sed -i '/^USE_WS=/d' .env` (new binary has no `--use-ws` flag at all).
  - Backed up old `.env` to `.env.bak-<timestamp>` first.
- **Second boot:** clean. `21:44:28Z` startup. Logs show:
  - `fidonext-relay: starting listen_addr=/ip4/0.0.0.0/tcp/41000 force_hop=true use_quic=false bootstrap_count=2`
  - `fidonext-relay: peer identity peer_id=12D3KooWHq7BXHFUP75JKZUwqNozsNyEXyTjrmjPjUKt8RDeJcTV` — **matches pre-upgrade** (profile volume preserved).
  - `fidonext-relay: listening listen_addr=/ip4/0.0.0.0/tcp/41000`
  - `subscribed to topic topic=/fidonext/nickname-registry/v1`
  - `relay reservation accepted` from relay-01 and relay-02 within 30 ms.
- **External TCP probe (from laptop):** `nc -vz 217.65.5.241 41000` → OK.
- **30-min observation (21:44Z → 22:18Z):**
  - `docker inspect`: Up, 0 restarts, 0 OOM.
  - `grep -cE 'ERROR |panic|FATAL'` → **0** across 4.1k log lines.
  - `grep -c NoPeersSubscribedToTopic` → **0**.
  - `subscribed to topic` events → 1 (at startup, as expected).
  - `relay reservation accepted` → 3 (steady reservation-renew cadence from bootstrap peers).
  - WARNs observed: benign TD-25 routing-table pollution (10.0.2.x Android emulator / 192.168.x LAN addresses gossiped via identify, then failing to dial), drive-by transport-negotiation failures from residential ISPs. Same pattern relay-03 showed on 2026-04-21 bring-up; not a regression.

### 3.2 relay-01 — second upgrade

- **Pre-upgrade state (21:45Z probe):** container `fidonext-relay` Up 4 d on `fidonext-relay:local` (Python wrapper). PeerId `12D3KooWPmi5RBj7TyrbErHNqRjTdqBusFpxyN8dnyv3hnp2TyuF`.
- **Source transfer:** `apt install rsync`, then rsync `c-abi-libp2p/` to `/opt/fidonext-relay/src/c-abi-libp2p/`.
- **Build:** `cd /opt/fidonext-relay/src && docker build -t fidonext-relay:local -f c-abi-libp2p/deploy/relay/Dockerfile .` → `Finished 'release' profile [optimized] target(s) in 6m 54s`. Full wall clock **445 s** (7 min 25 s). Image sha `c6d03cacc471…`. (Shared between relay-01 and relay-02 since both containers reference `fidonext-relay:local` on the same Docker engine.)
- **`.env` patch:** same pattern as relay-03. `USE_QUIC=0 → false`; `USE_WS=0` line removed.
- **Recreate:** `docker compose up -d --force-recreate relay`. Started `21:54:44Z`. Logs show:
  - `peer identity peer_id=12D3KooWPmi5RBj7TyrbErHNqRjTdqBusFpxyN8dnyv3hnp2TyuF` — **matches pre-upgrade**.
  - `subscribed to topic topic=/fidonext/nickname-registry/v1`
  - `listening` on `/ip4/0.0.0.0/tcp/41000`.
  - Relay reservation with relay-02 re-established within 100 ms.
- **External TCP probe:** `nc -vz 217.65.5.134 41000` → OK.
- **20-min observation (21:54Z → 22:18Z):**
  - Up, 0 restarts, 0 OOM.
  - 0 ERROR/panic/FATAL across 4.2k log lines.
  - 0 `NoPeersSubscribedToTopic`.
  - 1 startup `subscribed to topic` event (as expected).
  - WARNs benign (same TD-25 pollution pattern; also a one-shot `listener closed ... NoAddressesInReservation` around 22:02:26Z when relay-02 dropped out during its own recreate — self-healing).

### 3.3 relay-02 — third upgrade

- **Pre-upgrade state (21:45Z probe):** container `fidonext-relay-02` Up 4 d on `fidonext-relay:local` (Python wrapper). PeerId `12D3KooWHrer1b2yrE5GaiHiJp3G3UtsxkG8KfwZdZLZSk95YY8S`.
- **Source transfer + build:** N/A — image already rebuilt during relay-01 step (same tag, same Docker engine).
- **Compose patch:** relay-02's `docker-compose.yml` hard-codes `USE_QUIC: "0"` (instead of using an `.env`). Applied `sed -i 's/USE_QUIC: "0"/USE_QUIC: "false"/' docker-compose.yml` and `sed -i '/USE_WS: /d' docker-compose.yml`. Backed up old file to `docker-compose.yml.bak-<ts>`.
- **Recreate:** `docker compose up -d --force-recreate relay`. Started `22:02:28Z`. Logs show:
  - `peer identity peer_id=12D3KooWHrer1b2yrE5GaiHiJp3G3UtsxkG8KfwZdZLZSk95YY8S` — **matches pre-upgrade**.
  - `subscribed to topic topic=/fidonext/nickname-registry/v1`
  - `listening` on `/ip4/0.0.0.0/tcp/41001`.
  - Immediately established connections to relay-01 and relay-03; reservation accepted from relay-01 within 3 ms.
- **External TCP probe:** `nc -vz 217.65.5.134 41001` → OK.
- **15-min observation (22:02Z → 22:17Z):**
  - Up, 0 restarts, 0 OOM.
  - 0 ERROR/panic/FATAL.
  - 0 `NoPeersSubscribedToTopic`.
  - 1 startup `subscribed to topic` event.
  - One transient `ERROR failed to dial via relay circuit ... tried to dial local peer id` at T+7 ms — relay-02 briefly tried to dial itself-via-relay-01-circuit during identify/reservation bootstrap. Self-resolves on the next swarm tick; not a crash.
  - WARNs benign.

## 4. Rollback events

**None executed.** relay-03 entered a crash-loop during its first boot (old `USE_QUIC=0` incompatible with the new clap bool parser). Diagnosed within ~15 s, `.env` patched in-place, second boot clean. The `/data` volume was never deleted; PeerId preserved. No container was ever brought down for >30 s except during the intended force-recreate.

## 5. Client-side verification

Ran a local `fidonext-relay` (built from the same `8ad0fbb` on the dev laptop) against relay-03 as the sole bootstrap peer:

```
RUST_LOG=info,peer=info,libp2p_gossipsub=debug \
  ./target/release/fidonext-relay \
    --listen-addr /ip4/127.0.0.1/tcp/42999 \
    --profile-path /tmp/td01-rollout/client-test.profile.json \
    --bootstrap /ip4/217.65.5.241/tcp/41000/p2p/12D3KooWHq7BXHFUP75JKZUwqNozsNyEXyTjrmjPjUKt8RDeJcTV
```

Observed in the client log (within ~2 s of startup):

- `Subscribed to topic /fidonext/nickname-registry/v1` (local side).
- `SUBSCRIPTION: Adding peer to the mesh for topic peer=12D3KooWHq7BXHFU... topic=/fidonext/nickname-registry/v1` (relay-03 announces subscription).
- `SUBSCRIPTION: Adding peer to the mesh for topic peer=12D3KooWPmi5RBj7... topic=/fidonext/nickname-registry/v1` (relay-01, reached via relay-03's gossip).
- `SUBSCRIPTION: Adding peer to the mesh for topic peer=12D3KooWHrer1b2y... topic=/fidonext/nickname-registry/v1` (relay-02, same path).
- `Sending GRAFT` and `Handling GRAFT` completed for all three relays on both `echo` and `/fidonext/nickname-registry/v1`.
- `HEARTBEAT: Mesh low. Topic contains: 3 needs: 6` — the client's topic mesh stabilises at 3 peers, which is exactly the three-relay fleet. This is the expected post-TD-01 shape.
- **0 `NoPeersSubscribedToTopic`** events in the client log.

Log saved to `/tmp/td01-rollout/client-test.log` (local-only; not committed).

## 6. Inventory delta

Updated `.claude/secrets/relay-inventory.json` (gitignored) for all three entries:

| field | relay-01 | relay-02 | relay-03 |
|---|---|---|---|
| `image_source` | now "commit 8ad0fbb (TD-01 native Rust relay binary)" | same (shared image) | same |
| `last_deploy_at` | `2026-04-21T21:54:44Z` | `2026-04-21T22:02:28Z` | `2026-04-21T21:44:28Z` |
| `peer_id` | unchanged | unchanged | unchanged |
| `bootstrap_line` | unchanged | unchanged | unchanged |
| `status` | `live` (unchanged) | `live` (unchanged) | `live` (unchanged) |
| `image_tag` | `fidonext-relay:local` (unchanged) | same | same |

Bootstrap multiaddrs did not change, so **no Android `bootstrap_nodes.txt` edit is required.**

## 7. Follow-up QA / client-side verification

The next QA pass should confirm, from an Android build against the v0.0.7 release candidate:

1. **`NoPeersSubscribedToTopic` is gone from `adb logcat`** when publishing a nickname claim while the second peer is offline or on a different network:
   ```
   adb logcat -s Libp2pService:* cabi:* | grep -i "NoPeersSubscribedToTopic"
   ```
   Expected count: **0** over a 5-min claim/revoke cycle. (Pre-TD-01 this fired whenever the publisher's only relay peer was not subscribed to the registry topic.)
2. **Cross-network nickname convergence:** peer-A on Wi-Fi and peer-B on LTE, both bootstrapped to any one of the three relays. Claim a nickname on A, wait ≤10 s, observe the claim appears in B's registry state via `Libp2pService:*`. TD-40/TD-42 anti-entropy will retransmit the claim, but the mesh-level delivery should succeed on the first publish once all three relays are mesh members.
3. **Relay reservation churn check:** `docker logs fidonext-relay-03 | grep -c 'relay reservation accepted'` should keep climbing over hours as bootstrap peers renew (expect ≥1 every ~2 min per reserving peer).

## 8. What I did NOT change

- No `/data` volume deletion anywhere — all three relays kept their pre-upgrade libp2p identities.
- No git push, no commit to the `fidonext-core` tree, no push to any remote. Source commit `8ad0fbb` remains local to the dev laptop per task constraint.
- No SSH-key migration (test env, password auth per inventory policy).
- No Docker Hub publish — image remains `fidonext-relay:local`, built on each physical host.
- No edits to `fidonext_android/app/src/main/assets/bootstrap_nodes.txt` — bootstrap lines unchanged.
- No changes to relay-01's `BOOTSTRAP_PEERS` list (still points only at relay-02; does not include relay-03 yet). This is a pre-existing gap — relay-01 still relies on its K-buckets + DHT to discover relay-03. Not a TD-01 regression, but worth a fleet-wide mesh-bootstrap audit before prod.
- No QUIC/WS enablement. `USE_QUIC=false` across the fleet.
- No `SUBSCRIBE_TOPICS` override — binary-default `["/fidonext/nickname-registry/v1"]` used.

## 9. Risks flagged for system-architect / product-owner

1. **Shared image tag between relay-01 and relay-02 on kunzite VPS.** A rebuild triggered by either container's compose now affects both simultaneously. Today this is convenient; for prod, the image should be pinned by digest or moved to a Docker Hub tag per commit (`publish_dockerhub.sh` already exists for this).
2. **`USE_QUIC=0` value trap.** The new clap CLI rejects the pre-existing `.env` format from the Python-wrapper era. Any other dormant relay host brought up with an old `.env` will crash-loop on first start. Suggest documenting the breaking change in `deploy/relay/README.md` and/or accepting `0/1` in the `USE_QUIC` parser.
3. **Bootstrap list asymmetry on relay-01.** Its `.env` only lists relay-02 as a bootstrap; relay-02 lists only relay-01; relay-03 lists both. Mesh connectivity survives via DHT and gossip but a cold-start with relay-02 unreachable would starve relay-01 of bootstraps until relay-03 gossips in. Low priority, test-env only.
4. **v0.0.7 push:** this image includes commit `8ad0fbb` which is not yet on `origin/main`. The fleet is now running ahead of the public branch. When the v0.0.7 bundle is pushed, include `8ad0fbb` in the tag so future `docker build` runs from a clean checkout produce bit-identical binaries.

## 10. Next probe cadence

Recommend a 24-hour health re-probe (`docker ps`, `docker logs ... | grep -c NoPeers...`, `grep -c ERROR`) to confirm the fleet is stable over a full diurnal cycle. If clean, the fleet is ready to be handed off to QA for the v0.0.7 shipgate retry.
