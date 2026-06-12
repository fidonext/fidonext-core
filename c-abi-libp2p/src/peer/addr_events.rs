use libp2p::core::Multiaddr;

#[derive(Debug, Default)]
pub struct AddrState {
    listen: std::collections::HashSet<Multiaddr>,
    external_confirmed: std::collections::HashSet<Multiaddr>,
    relay_reachable: Option<Multiaddr>,
    version: u64,
}

/// Events happening with addreses of the peer
#[derive(Debug, Clone)]
pub enum AddrEvent {
    /// New local listen addr added
    /// Source: `SwarmEvent::NewListenAddr`
    /// May be not publicly reachable
    ListenerAdded { address: Multiaddr },

    /// Local listen addr was removed
    /// Source: `SwarmEvent::ListenerClosed`
    ListenerRemoved { address: Multiaddr },

    /// External publicly reachable addr
    /// added and confirmed
    /// Source: `SwarmEvent::ExternalAddrConfirmed`
    ExternalConfirmed { address: Multiaddr },

    /// External publicly reachable addr expired
    /// Source: `SwarmEvent::ExternalAddrExpired`
    ExternalExpired { address: Multiaddr },

    /// Relay-based addr is added and ready to use
    /// Source: `PeerManager::update_relay_address` (derived from relay reservation)
    RelayReachableReady { address: Multiaddr },

    /// Relay-reachable self address is no longer valid (reservation lost / expired)
    /// Source: `PeerManager::clear_relay_address` when current relay base is cleared
    RelayReachableLost,
}

impl AddrState {
    pub fn apply(&mut self, ev: &AddrEvent) {
        use AddrEvent::*;
        match ev {
            ListenerAdded { address } => {
                if self.listen.insert(address.clone()) {
                    self.version += 1;
                }
            }

            ListenerRemoved { address } => {
                if self.listen.remove(address) {
                    self.version += 1;
                }
            }

            ExternalConfirmed { address } => {
                if self.external_confirmed.insert(address.clone()) {
                    self.version += 1;
                }
            }

            ExternalExpired { address } => {
                if self.external_confirmed.remove(address) {
                    self.version += 1;
                }
            }

            RelayReachableReady { address } => {
                if self.relay_reachable.as_ref() != Some(address) {
                    self.relay_reachable = Some(address.clone());
                    self.version += 1;
                }
            }

            RelayReachableLost => {
                if self.relay_reachable.take().is_some() {
                    self.version += 1;
                }
            }
        }
    }

    // Public function to get cur version of snapshot for ABI
    pub fn version(&self) -> u64 {
        self.version
    }

    // Public function to give snapshot string of addreses for ABI
    pub fn snapshot_string(&self) -> String {
        let mut out: Vec<String> = Vec::new();

        if let Some(a) = &self.relay_reachable {
            out.push(a.to_string());
        }

        let mut ext: Vec<String> = self
            .external_confirmed
            .iter()
            .map(|a| a.to_string())
            .collect();
        ext.sort();
        out.extend(ext);

        let mut lis: Vec<String> = self.listen.iter().map(|a| a.to_string()).collect();
        lis.sort();
        out.extend(lis);

        out.join("\n")
    }
}
