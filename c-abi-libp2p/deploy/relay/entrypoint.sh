#!/usr/bin/env sh
set -eu

LISTEN_ADDR="${LISTEN_ADDR:-/ip4/0.0.0.0/tcp/41000}"
PROFILE_PATH="${PROFILE_PATH:-/data/relay.profile.json}"
EXTRA_ARGS="${EXTRA_ARGS:-}"
BOOTSTRAP_PEERS="${BOOTSTRAP_PEERS:-}"

CMD="python3 /app/ping_standalone_nodes.py --role relay --force-hop --listen ${LISTEN_ADDR}"

if [ "${USE_QUIC:-0}" = "1" ]; then
  CMD="$CMD --use-quic"
fi

if [ -n "${SEED_PHRASE:-}" ]; then
  CMD="$CMD --seed-phrase \"${SEED_PHRASE}\""
elif [ -n "${SEED_HEX:-}" ]; then
  CMD="$CMD --seed \"${SEED_HEX}\""
else
  CMD="$CMD --profile ${PROFILE_PATH}"
fi

if [ -n "${BOOTSTRAP_PEERS}" ]; then
  OLD_IFS="$IFS"
  IFS=","
  for peer in $BOOTSTRAP_PEERS; do
    CMD="$CMD --bootstrap \"${peer}\""
  done
  IFS="$OLD_IFS"
fi

if [ -n "${EXTRA_ARGS}" ]; then
  CMD="$CMD ${EXTRA_ARGS}"
fi

echo "[relay-entrypoint] starting relay with listen=${LISTEN_ADDR}"
echo "[relay-entrypoint] command: $CMD"
eval "$CMD"

