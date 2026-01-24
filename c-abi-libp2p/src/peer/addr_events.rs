
use anyhow::{anyhow, Result};
use libp2p::{core::Multiaddr, PeerId};
use tokio::sync::mpsc;

pub const DEFAULT_ADDR_EVENTS_CAPACITY: usize = 64;

/// Events happening with addreses of the peer
#[derive(Debug, Clone)]
pub enum AddrEvent {
    /// New local listen addr added
    /// Source: `SwarmEvent::NewListenAddr`
    /// May be not publicly reachable
    ListenAdded {
        address: Multiaddr,
    },

    /// External publicly reachable addr
    /// added and confirmed
    /// Source: `SwarmEvent::ExternalAddrConfirmed`
    ExternalConfirmed {
        address: Multiaddr,
    },

    /// External publicly reachable addr expired
    /// Source: `SwarmEvent::ExternalAddrExpired`
    ExtrnalExpired {
        address: Multiaddr,
    },

    /// Relay-based addr is added and ready to use
    /// 
    RelayReachableReady{
        address: Multiaddr,
    },
}

/// Queue used to pass addr events from the peer manager to the C-ABI.
#[derive(Debug)]
pub struct AddrEventQueue {
    sender: mpsc::Sender<AddrEvent>,
    receiver: mpsc::Receiver<AddrEvent>,
}

/// Cloneable sender handle for enqueuing addr events.
#[derive(Clone, Debug)]
pub struct AddrEventSender {
    sender: mpsc::Sender<AddrEvent>,
}

impl AddrEventQueue {
    /// Create a new `AddrEventQueue`
    pub fn new(capacity: usize) -> Self {
        let (sender, receiver) = mpsc::channel(capacity);
        Self { sender, receiver }
    }

    /// Get a copy of a sender for `AddrEventQueue`
    pub fn sender(&self) -> AddrEventSender {
        AddrEventSender {
            sender: self.sender.clone(),
        }
    }

    /// Try to get last event from the `AddrEventQueue`
    pub fn try_dequeue(&mut self) -> Option<AddrEvent> {
        self.receiver.try_recv().ok()
    }
}

impl AddrEventSender {
    /// Try to enqueue event in to `AddrEventQueue`
    pub fn try_enqueue(&self, event: AddrEvent) -> Result<()> {
        self.sender
            .try_send(event)
            .map_err(|err| anyhow!("failed to enqueue addr event: {err}"))
    }
}