//! Transport configuration and builders.

use anyhow::Result;

/// Placeholder transport builder.
#[derive(Debug, Default)]
pub struct TransportConfig {
    // TODO: configure libp2p transport stack
    pub use_quic: bool,
}

impl TransportConfig {
    /// Builds the transport stack using the current configuration.
    pub fn build(&self) -> Result<()> {
        // TODO: return an actual libp2p transport
        if self.use_quic {
            tracing::debug!(target: "transport", "QUIC support requested");
        }
        Ok(())
    }
}