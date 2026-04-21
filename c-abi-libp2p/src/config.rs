//! Global configuration helpers and defaults for the library.

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use tracing_subscriber::EnvFilter;

/// Default list of bootstrap peers used to connect to the network.
pub const DEFAULT_BOOTSTRAP_PEERS: &[&str] = &[];

static TRACING_INITIALIZED: OnceCell<()> = OnceCell::new();

/// Builds an [`EnvFilter`] from `RUST_LOG`, falling back to `info`.
///
/// TODO(TD-29): fallback to `filesDir/rust.env` when the env var is missing —
/// Android processes don't easily inherit env vars, and the QA rig in
/// `qa-artifacts/2026-04-21T0031Z-td26-requa/` was trying
/// `run-as … echo RUST_LOG=... > filesDir/rust.env`. Wiring that needs the
/// Android caller to hand us filesDir through `profile_path` or similar.
fn build_env_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Initializes the global [`tracing`] subscriber once per process.
///
/// Subsequent invocations become no-ops, making it safe to call from
/// different entry points without worrying about initialization order.
///
/// On Android (`target_os = "android"`) we install `tracing_android::layer`
/// so events reach `logcat`; everywhere else we stay on the default
/// `tracing_subscriber::fmt` stdout/stderr layer.
pub fn init_tracing() -> Result<()> {
    TRACING_INITIALIZED
        .get_or_try_init(|| {
            install_tracing()?;
            Ok(())
        })
        .map(|_| ())
}

#[cfg(target_os = "android")]
fn install_tracing() -> Result<()> {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = build_env_filter();
    let android_layer =
        tracing_android::layer("fidonext").map_err(|err| anyhow!("tracing-android init: {err}"))?;

    tracing_subscriber::registry()
        .with(filter)
        .with(android_layer)
        .try_init()
        .map_err(|err| anyhow!(err))?;
    Ok(())
}

#[cfg(not(target_os = "android"))]
fn install_tracing() -> Result<()> {
    use tracing_subscriber::fmt;

    fmt::Subscriber::builder()
        .with_env_filter(build_env_filter())
        .try_init()
        .map_err(|err| anyhow!(err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TD-29: on non-Android targets `init_tracing` must remain a safe
    /// idempotent no-op-on-second-call. The first call installs the fmt
    /// subscriber; any subsequent call is absorbed by `OnceCell`.
    #[test]
    fn init_tracing_is_idempotent_on_desktop() {
        // Either this call succeeds installing the subscriber, or another
        // test in the same process already installed one — both outcomes
        // are fine. The important invariant is that we don't panic.
        let _ = init_tracing();
        // Second call must be a no-op even if the first one installed.
        init_tracing().expect("second init_tracing call must be a no-op");
    }
}
