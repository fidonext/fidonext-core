#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-/opt/anaconda3/envs/fidonext-abi/bin/python}"
LOG_DIR="${SCRIPT_DIR}/logs/local_mesh"
RELAY_PORT="${RELAY_PORT:-41000}"
LEAF_A_PORT="${LEAF_A_PORT:-41001}"
LEAF_B_PORT="${LEAF_B_PORT:-41002}"
MESSAGE="${MESSAGE:-hello-from-shell}"
MESSAGE_DELAY="${MESSAGE_DELAY:-2}"
POST_MESSAGE_WAIT="${POST_MESSAGE_WAIT:-5}"
TRANSPORT="${TRANSPORT:-tcp}"

mkdir -p "${LOG_DIR}"
rm -f "${LOG_DIR}"/*.log 2>/dev/null || true

if [[ ! -x "${PYTHON_BIN}" ]]; then
    echo "[run_local_mesh] Python binary not found: ${PYTHON_BIN}" >&2
    exit 1
fi

if [[ "${TRANSPORT}" != "tcp" && "${TRANSPORT}" != "quic" ]]; then
    echo "[run_local_mesh] Unsupported TRANSPORT value: ${TRANSPORT} (use 'tcp' or 'quic')" >&2
    exit 1
fi

multiaddr() {
    local port="$1"
    if [[ "${TRANSPORT}" == "quic" ]]; then
        echo "/ip4/127.0.0.1/udp/${port}/quic-v1"
    else
        echo "/ip4/127.0.0.1/tcp/${port}"
    fi
}

QUIC_FLAGS=()
if [[ "${TRANSPORT}" == "quic" ]]; then
    QUIC_FLAGS=(--use-quic)
fi

wait_for_pattern() {
    local file="$1" pattern="$2" timeout="$3"
    local start
    start=$(date +%s)
    while true; do
        if [[ -f "${file}" ]] && grep -q "${pattern}" "${file}"; then
            return 0
        fi
        if (( "$(date +%s)" - start >= timeout )); then
            echo "[run_local_mesh] Timed out waiting for '${pattern}' in ${file}" >&2
            return 1
        fi
        sleep 1
    done
}

cleanup() {
    local exit_code=$?
    if [[ -n "${RELAY_PID:-}" ]]; then
        kill "${RELAY_PID}" 2>/dev/null || true
    fi
    if [[ -n "${LEAFB_PID:-}" ]]; then
        kill "${LEAFB_PID}" 2>/dev/null || true
    fi
    wait "${RELAY_PID:-}" 2>/dev/null || true
    wait "${LEAFB_PID:-}" 2>/dev/null || true
    exit "${exit_code}"
}

trap cleanup EXIT INT TERM

RELAY_LOG="${LOG_DIR}/relay.log"
LEAF_A_LOG="${LOG_DIR}/leafA.log"
LEAF_B_LOG="${LOG_DIR}/leafB.log"
RELAY_ADDR="$(multiaddr "${RELAY_PORT}")"
LEAF_A_ADDR="$(multiaddr "${LEAF_A_PORT}")"
LEAF_B_ADDR="$(multiaddr "${LEAF_B_PORT}")"

echo "[run_local_mesh] Starting relay on port ${RELAY_PORT}..."
"${PYTHON_BIN}" -u "${PROJECT_ROOT}/examples/python/ping_standalone_nodes.py" \
    --role relay \
    --listen "${RELAY_ADDR}" \
    --seed-phrase relay-local \
    "${QUIC_FLAGS[@]}" >"${RELAY_LOG}" 2>&1 &
RELAY_PID=$!

wait_for_pattern "${RELAY_LOG}" "Local PeerId" 20 || { cat "${RELAY_LOG}"; exit 1; }
RELAY_ID=$(grep -m1 "Local PeerId" "${RELAY_LOG}" | awk '{print $3}')
if [[ -z "${RELAY_ID}" ]]; then
    echo "[run_local_mesh] Failed to parse relay PeerId" >&2
    cat "${RELAY_LOG}"
    exit 1
fi
echo "[run_local_mesh] Relay PeerId: ${RELAY_ID}"
BOOTSTRAP="${RELAY_ADDR}/p2p/${RELAY_ID}"

sleep 2

echo "[run_local_mesh] Starting leaf B on port ${LEAF_B_PORT}..."
"${PYTHON_BIN}" -u "${PROJECT_ROOT}/examples/python/ping_standalone_nodes.py" \
    --listen "${LEAF_B_ADDR}" \
    --bootstrap "${BOOTSTRAP}" \
    --seed-phrase peer-b-local \
    "${QUIC_FLAGS[@]}" >"${LEAF_B_LOG}" 2>&1 &
LEAFB_PID=$!
wait_for_pattern "${LEAF_B_LOG}" "Dialed bootstrap peer" 20 || { cat "${LEAF_B_LOG}"; exit 1; }
wait_for_pattern "${LEAF_B_LOG}" "connection established" 20 || { cat "${LEAF_B_LOG}"; exit 1; }

sleep 5

echo "[run_local_mesh] Running leaf A on port ${LEAF_A_PORT} and publishing payload..."
"${PYTHON_BIN}" -u "${PROJECT_ROOT}/examples/python/ping_standalone_nodes.py" \
    --listen "${LEAF_A_ADDR}" \
    --bootstrap "${BOOTSTRAP}" \
    --seed-phrase peer-a-local \
    --message "${MESSAGE}" \
    --message-delay "${MESSAGE_DELAY}" \
    --post-message-wait "${POST_MESSAGE_WAIT}" \
    "${QUIC_FLAGS[@]}" >"${LEAF_A_LOG}" 2>&1 || true

wait_for_pattern "${LEAF_B_LOG}" "Received payload" 20 || {
    echo "[run_local_mesh] Leaf B did not receive payload in time." >&2
    cat "${LEAF_B_LOG}"
    exit 1
}
echo "[run_local_mesh] Leaf B received payload."

echo "[run_local_mesh] Logs stored in ${LOG_DIR}"

