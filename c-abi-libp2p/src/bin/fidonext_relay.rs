//! TD-01 · `fidonext-relay` — native Rust relay binary.
//!
//! Replaces the prior relay Docker image's Python wrapper around
//! `examples/python/ping_standalone_nodes.py`. Drives [`PeerManager`]
//! directly (no FFI) with relay-server (hop) on, subscribes to the
//! application-level gossipsub topics required for cross-network
//! peer convergence (notably `/fidonext/nickname-registry/v1`), and
//! runs until `Ctrl+C` is received.
//!
//! The earlier Python-wrapper image never subscribed the relay node to
//! `/fidonext/nickname-registry/v1`, which meant gossipsub mesh formation
//! for the registry topic was limited to whichever pair of clients happened
//! to be directly connected. QA artifact
//! `qa-artifacts/2026-04-21T2107Z-td42-shipgate-retry/` captured the
//! resulting `NoPeersSubscribedToTopic` symptom across Wi-Fi↔LTE peers.
//! Having the relays participate in the registry mesh is the fix.
//!
//! Env-var friendly flags (via `clap(env = "…")`) keep the Docker
//! entrypoint thin; see `deploy/relay/entrypoint.sh`.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use cabi_rust_libp2p::{
    e2ee, AddrState, DiscoveryQueue, FileTransferQueue, MessageQueue, PeerManager, TransportConfig,
    DEFAULT_DISCOVERY_QUEUE_CAPACITY, DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY,
    DEFAULT_MESSAGE_QUEUE_CAPACITY,
};
use clap::Parser;
use libp2p::Multiaddr;
use tokio::signal;
use tracing_subscriber::EnvFilter;

/// Default application-level gossipsub topics the relay must join if no
/// `--subscribe-topic` overrides were supplied on the CLI. The registry
/// topic is the blocker identified by
/// `qa-artifacts/2026-04-21T2107Z-td42-shipgate-retry/` — without relay
/// subscription, cross-network peers cannot converge. Keep this list
/// small and explicit; every extra default is traffic every relay forwards.
const DEFAULT_SUBSCRIBE_TOPICS: &[&str] = &["/fidonext/nickname-registry/v1"];

/// Default TCP listen multiaddr when `--listen-addr` is not supplied.
const DEFAULT_LISTEN_ADDR: &str = "/ip4/0.0.0.0/tcp/41000";

#[derive(Debug, Parser)]
#[command(
    name = "fidonext-relay",
    about = "fidonext-core libp2p relay node (TD-01). Native Rust binary replacing the prior Python-wrapper relay image.",
    version
)]
struct RelayArgs {
    /// TCP multiaddr to listen on. Example: `/ip4/0.0.0.0/tcp/41000`.
    #[arg(long, env = "LISTEN_ADDR", default_value = DEFAULT_LISTEN_ADDR)]
    listen_addr: String,

    /// Bootstrap peer multiaddrs (repeatable). Each value must end with
    /// `/p2p/<peer_id>`. Used to seed Kademlia and to auto-reserve a
    /// relay slot (TD-30) against another super-peer.
    #[arg(long = "bootstrap", value_name = "MULTIADDR")]
    bootstrap: Vec<String>,

    /// Force hop-relay (relay server) mode on. Relay nodes should always
    /// pass this flag; regular clients should not.
    #[arg(long = "force-hop", env = "FORCE_HOP", default_value_t = true)]
    force_hop: bool,

    /// Path to the JSON identity profile. Auto-created with a fresh seed
    /// on first run; subsequent runs reuse the same libp2p identity so the
    /// relay's PeerId is stable across restarts.
    #[arg(long, env = "PROFILE_PATH", default_value = "/data/relay.profile.json")]
    profile_path: PathBuf,

    /// Gossipsub topics to subscribe to (repeatable). When supplied, the
    /// default list is replaced entirely — pass `/fidonext/nickname-registry/v1`
    /// explicitly if you still want it in the mesh.
    #[arg(long = "subscribe-topic", value_name = "TOPIC")]
    subscribe_topic: Vec<String>,

    /// `tracing_subscriber` filter string. Same shape as `RUST_LOG` (e.g.
    /// `info,peer=debug,libp2p_gossipsub=debug`).
    #[arg(long, env = "RUST_LOG", default_value = "info,peer=info,ffi=info")]
    log_level: String,

    /// Enable QUIC transport alongside TCP. Off by default — the production
    /// relay fabric runs TCP-only to keep the Caddy/Hetzner frontend simple.
    #[arg(long, env = "USE_QUIC", default_value_t = false)]
    use_quic: bool,
}

impl RelayArgs {
    /// Returns the effective list of gossipsub topics to subscribe to,
    /// falling back to [`DEFAULT_SUBSCRIBE_TOPICS`] if the caller passed
    /// nothing on the CLI. Deduped.
    fn effective_subscribe_topics(&self) -> Vec<String> {
        let mut topics = if self.subscribe_topic.is_empty() {
            DEFAULT_SUBSCRIBE_TOPICS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>()
        } else {
            self.subscribe_topic.clone()
        };
        // Keep insertion order but drop duplicates — a repeated `--subscribe-topic`
        // would be a no-op on gossipsub anyway, but we log one line per topic
        // at startup and the dedup cleans that up.
        let mut seen = std::collections::HashSet::new();
        topics.retain(|t| seen.insert(t.clone()));
        topics
    }
}

fn init_tracing(filter: &str) {
    let env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();
}

fn parse_bootstrap_peers(raw: &[String]) -> Result<Vec<Multiaddr>> {
    raw.iter()
        .map(|s| {
            s.parse::<Multiaddr>()
                .with_context(|| format!("invalid bootstrap multiaddr: {s}"))
        })
        .collect()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let args = RelayArgs::parse();
    init_tracing(&args.log_level);

    tracing::info!(
        listen_addr = %args.listen_addr,
        force_hop = args.force_hop,
        use_quic = args.use_quic,
        profile_path = %args.profile_path.display(),
        bootstrap_count = args.bootstrap.len(),
        "fidonext-relay: starting"
    );

    // 1. Identity profile — reused across restarts so the relay PeerId
    //    stays stable. `load_or_create_profile` creates parents if needed
    //    inside `persist_profile`.
    if let Some(parent) = args.profile_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create profile parent directory {}",
                    parent.display()
                )
            })?;
        }
    }
    let profile = e2ee::load_or_create_profile(&args.profile_path).with_context(|| {
        format!(
            "failed to load/create identity profile at {}",
            args.profile_path.display()
        )
    })?;

    // 2. TransportConfig — TCP by default, QUIC optional, hop-relay on.
    let config =
        TransportConfig::new(args.use_quic, args.force_hop).with_identity_seed(profile.libp2p_seed);

    // 3. Queues. The relay does not surface messages, file transfers, or
    //    discovery events to any caller, but the `PeerManager::new` signature
    //    requires the senders. Keep the queues alive on the stack so their
    //    sender halves stay valid for the lifetime of the process.
    let message_queue = MessageQueue::new(DEFAULT_MESSAGE_QUEUE_CAPACITY);
    let file_transfer_queue = FileTransferQueue::new(DEFAULT_FILE_TRANSFER_QUEUE_CAPACITY);
    let discovery_queue = DiscoveryQueue::new(DEFAULT_DISCOVERY_QUEUE_CAPACITY);
    let addr_state = Arc::new(RwLock::new(AddrState::default()));

    // 4. Bootstrap peers.
    let bootstrap_peers = parse_bootstrap_peers(&args.bootstrap)?;
    for addr in &bootstrap_peers {
        tracing::info!(%addr, "bootstrap peer configured");
    }

    // 5. Spawn the manager. TD-37 nickname-event queue is intentionally
    //    left `None` — the relay is not a client and has no need to surface
    //    ownership-revoked events; registry messages are still observed and
    //    forwarded by virtue of the gossipsub subscription below.
    let (manager, handle) = PeerManager::new(
        config,
        message_queue.sender(),
        file_transfer_queue.sender(),
        discovery_queue.sender(),
        None,
        addr_state,
        bootstrap_peers,
    )
    .context("failed to construct PeerManager")?;

    tracing::info!(peer_id = %handle.local_peer_id(), "fidonext-relay: peer identity");

    let manager_task = tokio::spawn(async move { manager.run().await });

    // 6. Start listening.
    let listen_addr: Multiaddr = args
        .listen_addr
        .parse()
        .with_context(|| format!("invalid --listen-addr: {}", args.listen_addr))?;
    handle
        .start_listening(listen_addr.clone())
        .await
        .context("start_listening failed")?;
    tracing::info!(%listen_addr, "fidonext-relay: listening");

    // 7. Subscribe to application-level topics. Built-in `echo` and the
    //    nickname-registry topic are already subscribed by `PeerManager::new`;
    //    the anti-entropy registry topic is in `DEFAULT_SUBSCRIBE_TOPICS`
    //    anyway so re-subscribing it is a logged no-op. Any additional
    //    operator-supplied topics land here.
    let topics = args.effective_subscribe_topics();
    for topic in &topics {
        handle
            .subscribe_topic(topic.clone())
            .await
            .with_context(|| format!("failed to subscribe to gossipsub topic: {topic}"))?;
        tracing::info!(%topic, "subscribed to topic");
    }

    // 8. Block on Ctrl+C and request graceful shutdown on exit.
    signal::ctrl_c()
        .await
        .context("failed to install ctrl_c handler")?;
    tracing::info!("fidonext-relay: ctrl_c received, shutting down");

    if let Err(err) = handle.shutdown().await {
        tracing::warn!(%err, "shutdown command enqueue failed");
    }

    match manager_task.await {
        Ok(Ok(())) => tracing::info!("fidonext-relay: manager task exited cleanly"),
        Ok(Err(err)) => tracing::error!(%err, "fidonext-relay: manager task failed"),
        Err(err) => tracing::error!(%err, "fidonext-relay: manager task panicked"),
    }

    // Explicitly keep the queues alive until here so the senders held by
    // the manager don't observe a receiver-drop before shutdown completes.
    drop(message_queue);
    drop(file_transfer_queue);
    drop(discovery_queue);

    Ok(())
}

#[cfg(test)]
mod tests {
    //! TD-01 · CLI-level unit tests.
    //!
    //! These validate the parser surface and the defaulting behaviour that
    //! the Docker entrypoint relies on. The actual startup path
    //! (listen + subscribe + shutdown) is exercised by the manual smoke
    //! recipe documented in the task report.
    use super::*;
    use clap::Parser;

    #[test]
    fn default_subscribe_topics_include_nickname_registry() {
        // Regression guard for the motivating TD-01 symptom:
        // `qa-artifacts/2026-04-21T2107Z-td42-shipgate-retry/` proved the
        // relay fabric did not join the nickname-registry topic mesh, so
        // cross-network clients saw `NoPeersSubscribedToTopic`. If the
        // default list ever drops the registry topic, TD-01 is effectively
        // regressed.
        assert!(
            DEFAULT_SUBSCRIBE_TOPICS
                .iter()
                .any(|t| *t == "/fidonext/nickname-registry/v1"),
            "default subscribe topic list must contain the nickname registry topic",
        );
    }

    #[test]
    fn parser_accepts_bare_invocation_with_defaults() {
        // `fidonext-relay` with no flags must parse and pick the documented
        // defaults. The Docker entrypoint relies on this: if env vars are
        // absent it falls back to these.
        let args = RelayArgs::parse_from(["fidonext-relay"]);
        assert_eq!(args.listen_addr, DEFAULT_LISTEN_ADDR);
        assert!(args.bootstrap.is_empty());
        assert!(args.force_hop, "relay binary must default to hop-relay on");
        assert!(!args.use_quic, "QUIC must be off by default");
        assert!(args.subscribe_topic.is_empty());
        let effective = args.effective_subscribe_topics();
        assert_eq!(
            effective,
            vec!["/fidonext/nickname-registry/v1".to_string()]
        );
    }

    #[test]
    fn parser_accepts_multiple_bootstrap_and_topic_flags() {
        // Repeatable `--bootstrap` / `--subscribe-topic` are the entrypoint's
        // way of passing a BOOTSTRAP_PEERS / SUBSCRIBE_TOPICS list, so the
        // flag must be `clap::ArgAction::Append`-shaped.
        let args = RelayArgs::parse_from([
            "fidonext-relay",
            "--listen-addr",
            "/ip4/127.0.0.1/tcp/0",
            "--bootstrap",
            "/ip4/1.2.3.4/tcp/41000/p2p/12D3KooWPmi5FwJGNRv4NKNe4jJvgepdPHfuAhFWBczbMmDkvD3k",
            "--bootstrap",
            "/ip4/5.6.7.8/tcp/41000/p2p/12D3KooWFUBpUgGywZPur3ayuX1XrTi1xX1WZT5ighvvRKuxfEX4",
            "--subscribe-topic",
            "/fidonext/nickname-registry/v1",
            "--subscribe-topic",
            "/fidonext/custom-channel/v1",
        ]);
        assert_eq!(args.listen_addr, "/ip4/127.0.0.1/tcp/0");
        assert_eq!(args.bootstrap.len(), 2);
        assert_eq!(args.subscribe_topic.len(), 2);
        let effective = args.effective_subscribe_topics();
        assert_eq!(
            effective,
            vec![
                "/fidonext/nickname-registry/v1".to_string(),
                "/fidonext/custom-channel/v1".to_string(),
            ],
        );
    }

    #[test]
    fn subscribe_topic_flags_override_defaults() {
        // When the operator supplies `--subscribe-topic`, they take over the
        // list — if they forget the registry topic, they forget it
        // intentionally. This is explicit so tests and ad-hoc operators can
        // minimise the relay's fanout without surprise defaults.
        let args = RelayArgs::parse_from([
            "fidonext-relay",
            "--subscribe-topic",
            "/fidonext/only-this/v1",
        ]);
        assert_eq!(
            args.effective_subscribe_topics(),
            vec!["/fidonext/only-this/v1".to_string()],
        );
    }

    #[test]
    fn effective_topics_are_deduplicated() {
        // Two `--subscribe-topic` flags with the same value must collapse to
        // one — gossipsub's `SubscriptionError::AlreadySubscribed` handling
        // tolerates duplicates, but logging N times is noisy.
        let args = RelayArgs::parse_from([
            "fidonext-relay",
            "--subscribe-topic",
            "/fidonext/a/v1",
            "--subscribe-topic",
            "/fidonext/a/v1",
            "--subscribe-topic",
            "/fidonext/b/v1",
        ]);
        let effective = args.effective_subscribe_topics();
        assert_eq!(
            effective,
            vec!["/fidonext/a/v1".to_string(), "/fidonext/b/v1".to_string()],
        );
    }

    #[test]
    fn parse_bootstrap_peers_rejects_garbage() {
        // The entrypoint forwards env-var-derived multiaddrs verbatim. A
        // typo in BOOTSTRAP_PEERS should hard-fail at startup, not silently
        // produce an unreachable relay.
        let result = parse_bootstrap_peers(&["not-a-multiaddr".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_bootstrap_peers_accepts_valid_list() {
        let result = parse_bootstrap_peers(&[
            "/ip4/1.2.3.4/tcp/41000/p2p/12D3KooWPmi5FwJGNRv4NKNe4jJvgepdPHfuAhFWBczbMmDkvD3k"
                .to_string(),
        ])
        .expect("valid multiaddr parse");
        assert_eq!(result.len(), 1);
    }
}
