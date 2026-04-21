#!/usr/bin/env sh
# TD-01 · entrypoint for the native Rust relay image.
#
# Translates env-vars into `fidonext-relay` CLI flags and execs the binary.
# Env-var names are preserved where possible from the prior Python-wrapper
# entrypoint so existing `docker-compose.yml` overrides keep working. New
# since TD-01: `SUBSCRIBE_TOPICS` (whitespace-separated topic list).

set -eu

LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/41000}"
PROFILE_PATH="${PROFILE_PATH:-/data/relay.profile.json}"
RUST_LOG="${RUST_LOG:-info,peer=info}"
FORCE_HOP="${FORCE_HOP:-true}"
USE_QUIC="${USE_QUIC:-0}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
# Backwards-compat: previous image used BOOTSTRAP_PEERS (comma-separated).
# New images may use BOOTSTRAP_LIST (comma- OR space-separated). Both work.
BOOTSTRAP_PEERS="${BOOTSTRAP_PEERS:-${BOOTSTRAP_LIST:-}}"
# Whitespace- OR comma-separated list of gossipsub topics to subscribe to.
# When empty, `fidonext-relay` falls back to its built-in defaults (today
# just `/fidonext/nickname-registry/v1`).
SUBSCRIBE_TOPICS="${SUBSCRIBE_TOPICS:-}"

# Build the argv one flag at a time. Using `set --` avoids quoting landmines
# when multiaddrs contain slashes and the like.
set -- --listen-addr "$LISTEN_ADDR" --profile-path "$PROFILE_PATH" --log-level "$RUST_LOG"

case "$FORCE_HOP" in
  true|TRUE|1|yes|YES)
    set -- "$@" --force-hop
    ;;
  *)
    # clap's `--force-hop` is a bool flag with a default_value_t of `true`.
    # To disable, we pass `--force-hop=false` so clap's ValueParser picks the
    # explicit value rather than the default.
    set -- "$@" --force-hop=false
    ;;
esac

case "$USE_QUIC" in
  1|true|TRUE|yes|YES)
    set -- "$@" --use-quic
    ;;
esac

if [ -n "$BOOTSTRAP_PEERS" ]; then
  OLD_IFS="$IFS"
  # Support both commas and whitespace as separators.
  IFS=", 	"
  for peer in $BOOTSTRAP_PEERS; do
    [ -z "$peer" ] && continue
    set -- "$@" --bootstrap "$peer"
  done
  IFS="$OLD_IFS"
fi

if [ -n "$SUBSCRIBE_TOPICS" ]; then
  OLD_IFS="$IFS"
  IFS=", 	"
  for topic in $SUBSCRIBE_TOPICS; do
    [ -z "$topic" ] && continue
    set -- "$@" --subscribe-topic "$topic"
  done
  IFS="$OLD_IFS"
fi

if [ -n "$EXTRA_ARGS" ]; then
  # EXTRA_ARGS is intentionally word-split here so operators can append
  # things like `--subscribe-topic /fidonext/foo/v1` without us parsing it.
  # shellcheck disable=SC2086
  set -- "$@" $EXTRA_ARGS
fi

echo "[relay-entrypoint] starting fidonext-relay"
echo "[relay-entrypoint] listen=$LISTEN_ADDR profile=$PROFILE_PATH force_hop=$FORCE_HOP"
echo "[relay-entrypoint] argv: $*"

exec /usr/local/bin/fidonext-relay "$@"
