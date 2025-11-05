//! Global configuration helpers and defaults for the library.

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use tracing_subscriber::{fmt, EnvFilter};

/// Default list of bootstrap peers used to connect to the network.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[];

static TRACING_INITIALIZED: OnceCell<()> = OnceCell::new();

/// Initializes the global [`tracing`] subscriber once per process.
///
/// Subsequent invocations become no-ops, making it safe to call from
/// different entry points without worrying about initialization order.
pub fn init_tracing() -> Result<()> {
    TRACING_INITIALIZED
        .get_or_try_init(|| {
            let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
            fmt::Subscriber::builder()
                .with_env_filter(env_filter)
                .try_init()
                .map_err(|err| anyhow!(err))?;
            Ok(())
        })
        .map(|_| ())
}