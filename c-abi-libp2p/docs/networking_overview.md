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
   - If `TransportConfig` was constructed with `with_identity`, the provided key is reused.
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
- Because the same keypair always produces the same `PeerId`, reusing it across launches keeps the node's identity stable.

## 4. Related tests

- `tests/peer_manager.rs` contains integration-test scaffolding.
- Unit tests in `src/transport/libp2p.rs` and `src/peer/manager.rs` assert that the `PeerId` matches the public key.

This layout mirrors the steps described in the official libp2p tutorial while keeping the project code organised into focused modules.