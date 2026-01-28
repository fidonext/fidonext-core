# Networking stack overview

This project uses [`libp2p`](https://libp2p.io/) to build a peer-to-peer network. Two source files contain the key pieces of logic:

- `src/transport/libp2p.rs` – configures the transport and bundled protocols (how we connect to the network).
- `src/peer/manager.rs` – owns the `Swarm`, receives commands, and reacts to network events.

The sections below walk through the path the code takes when a node is created.

## 1. Building the transport and behaviour

```text
TransportConfig::build() → (identity::Keypair, Swarm<NetworkBehaviour>)
```

1. **Choose or generate the identity key.**
   - If `TransportConfig` was constructed with `with_identity_seed`, the provided 32-byte seed is used to derive an `Ed25519` keypair.
   - Otherwise a new `Ed25519` keypair is generated. Its public key defines the local `PeerId`.
2. **Create the transport.**
   - By default we compose TCP + Noise + Yamux.
   - When `use_quic = true`, QUIC is also enabled and combined with TCP via `or_transport`.
3. **Bundle the behaviour protocols.**
   - `Kademlia` – distributed hash table for peer discovery.
   - `Ping` – connectivity check between peers.
   - `Identify` – exchange version and address information.
4. **Initialise the `Swarm`.**
   - `Swarm::with_tokio_executor` receives the transport, behaviour, and local `PeerId`.
   - The method returns `(keypair, swarm)` so `PeerManager` can remember the identity key alongside the ready-to-use `Swarm`.

## 2. Creating and running the peer manager

```text
PeerManager::new(config, bootstrap_peers) → (PeerManager, PeerManagerHandle)
```

1. **Retrieve the `Swarm` and keypair.** `TransportConfig::build` yields both values.
2. **Store the `PeerId`.** `PeerManager` keeps the `PeerId` and `Keypair` so other parts of the program can access the identity.
3. **Set up the command channel.** An `mpsc` channel with a capacity of 32 is created; `PeerManagerHandle` wraps the sender side.
4. **Seed the DHT.** Bootstrap multiaddrs supplied via FFI (plus any compiled defaults) are registered with Kademlia and an initial `bootstrap` query is fired so the node joins the network immediately.

```text
PeerManager::run() — asynchronous loop
```

- `tokio::select!` listens to **commands** and **network events** simultaneously.
- Commands (`PeerCommand`) allow other tasks to:
  - start listening on an address (`StartListening`),
  - dial a peer (`Dial`),
  - stop the manager (`Shutdown`).
- `SwarmEvent`s are logged and forwarded to `handle_behaviour_event` so we can observe notifications from `Kademlia`, `Ping`, and `Identify`.

### AutoNAT reachability hints

- `PeerManager` subscribes to `BehaviourEvent::Autonat` and stores the most recent `NatStatus` update (public, private, or unknown) in a watch channel.
- The new C-ABI helper `cabi_autonat_status` exposes that status to clients
- Client apps can watch the status and restart the node with `hop_relay = true` once AutoNAT reports a public address, enabling relay services after public reachability is confirmed.

## 3. Where the network identity comes from

- During start-up `TransportConfig::build` picks or generates an `identity::Keypair`.
- The `PeerId` derived from that key is stored inside `PeerManager`.
- The identity can be accessed through:
  - `PeerManager::peer_id()` – returns the `PeerId`.
  - `PeerManager::keypair()` – returns the keypair (e.g. for persistence).
- Because the same keypair always produces the same `PeerId`, reusing it across launches keeps the node's identity stable. Passing the same `identity_seed` to peers on both ends is enough to get deterministic keypairs and predictable connection setup paths.

## Example: deterministic identity configuration

```rust
use cabi_rust_libp2p::transport::TransportConfig;

let seed = [0u8; 32];
let config = TransportConfig::new(true, false).with_identity_seed(seed);
let (keypair, swarm) = config.build()?;
```

Sharing the same seed between two nodes yields identical `PeerId`s so tests and reproducible environments can coordinate deterministic connections.

## 4. Related tests

- `tests/peer_manager.rs` contains integration-test scaffolding.
- Unit tests in `src/transport/libp2p.rs` and `src/peer/manager.rs` assert that the `PeerId` matches the public key.

This layout mirrors the steps described in the official libp2p tutorial while keeping the project code organised into focused modules.

## 5. C-ABI dequeue event APIs (short reference)

These functions poll FIFO queues owned by the node. Each returns a `CABI_STATUS_*` code and writes to out-parameters on success (or to report required buffer sizes).

### What functions exist and what they do

- `cabi_node_dequeue_message`: pops the next message payload into `out_buffer`.
- `cabi_node_dequeue_discovery_event`: pops the next Kademlia discovery event (address found or query finished).
- `cabi_node_dequeue_addr_event`: pops the next address-related event (listen/external/relay-ready).

### How to use

1. Call the dequeue function in a polling loop.
2. If it returns `CABI_STATUS_QUEUE_EMPTY`, wait and retry.
3. If it returns `CABI_STATUS_BUFFER_TOO_SMALL`, resize the target buffer to the reported `*_written_len` and call again.
4. On `CABI_STATUS_SUCCESS`, read the out-parameters and continue.

### Status codes

- `CABI_STATUS_SUCCESS`: event/message written to out-params.
- `CABI_STATUS_QUEUE_EMPTY`: no event/message available.
- `CABI_STATUS_NULL_POINTER`: required pointer is null.
- `CABI_STATUS_INVALID_ARGUMENT`: invalid input (e.g., zero-length buffer).
- `CABI_STATUS_BUFFER_TOO_SMALL`: buffer too small; `*_written_len` reports required length (bytes, excluding the null terminator for strings).

### Address event kinds (`cabi_node_dequeue_addr_event`)

- `CABI_ADDR_EVENT_LISTEN_ADDED`: started listening on a new address.
- `CABI_ADDR_EVENT_LISTEN_REMOVED`: listening address removed.
- `CABI_ADDR_EVENT_EXTERNAL_CONFIRMED`: AutoNAT confirmed an external address.
- `CABI_ADDR_EVENT_EXTERNAL_EXPIRED`: external address expired.
- `CABI_ADDR_EVENT_RELAY_READY`: relay-ready address is reachable.
