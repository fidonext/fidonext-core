# Python Examples

## `ping_two_nodes.py`

Small `ctypes` script that:

1. Loads the compiled `libcabi_rust_libp2p.so`.
2. Creates two nodes (`listener` and `dialer`) through the C ABI.
3. Starts TCP listeners and initiates a connection.
4. Gives the nodes time to exchange libp2p ping traffic.

### Environment setup

1. Activate the dedicated Conda environment for the project:
   ```bash
   conda activate fidonext-abi
   ```
2. Create a local virtual environment for the Python example:
   ```bash
   cd /home/georgeb/fidonext-core/c-abi-libp2p/examples/python
   bash setup_env.sh
   source .venv/bin/activate
   ```

### Run the example

1. Build the Rust shared library (produces `target/debug/libcabi_rust_libp2p.so`):
   ```bash
   cd /home/georgeb/fidonext-core/c-abi-libp2p
   cargo build
   ```
2. (Optional) Tweak logging for verbose ping output:
   ```bash
   export RUST_LOG="info,peer=debug,ffi=debug"
   ```
3. Execute the Python client-to-client ping test:
   ```bash
   python3 examples/python/ping_two_nodes.py
   ```
   To force QUIC instead of TCP, pass the `--use-quic` flag (the script will
   switch to `/udp/.../quic-v1` multiaddrs automatically):
   ```bash
   python3 examples/python/ping_two_nodes.py --use-quic
   ```
4. The dialer now publishes a payload via the Rust gossipsub bridge and the
   listener reads it through the FFI queue (`Received message from network
   queue`). This demonstrates cross-node delivery.
5. Observe the console: successful runs show both peers listening, dialing, and
   establishing a connection. Ping RTTs appear in the Rust logs when
   `peer=debug` is enabled. The script automatically shuts down both nodes after
   ~5 seconds, so you may see a final “connection closed” warning—this is
   expected during teardown.

* By default the script expects `target/debug/libcabi_rust_libp2p.so`. Override
  the location via the `FIDONEXT_C_ABI` environment variable.
* Rust logs (`peer` / `ffi`) surface connection events and ping RTTs.
* Additional CLI knobs: `--listener-port`, `--dialer-port`, and `--duration`
  (seconds to keep nodes alive after dialing).
* Example command pair for taking a QUIC capture while running the test
  (execute in two terminals):
  ```bash
  # Terminal 1: capture QUIC packets for 15 seconds
  sudo tshark -i lo -f "udp port 41000 or udp port 41001" \
      -a duration:15 -w /home/georgeb/fidonext-core/fidonext_ping.pcapng
  ```
  ```bash
  # Terminal 2: run the QUIC ping demo
  conda activate fidonext-abi
  cd /home/georgeb/fidonext-core/c-abi-libp2p
  RUST_LOG="info,peer=debug,ffi=debug" python3 examples/python/ping_two_nodes.py --use-quic
  ```

## `ping_standalone_nodes.py`

`ping_standalone_nodes.py` mirrors the C++ ping CLI but keeps exactly one node
per process/container. The script:

- matches the C++ switches (`--role`, `--force-hop`, `--listen`, `--bootstrap`,
  `--target`, `--seed`, `--seed-phrase`, `--use-quic`);
- prints the local `PeerId` and, for relays, restarts with hop enabled when
  AutoNAT reports PUBLIC reachability (or immediately when `--force-hop` is set);
- dials bootstrap and target peers after listening, then forwards stdin payloads
  to gossipsub while printing received messages from the queue.

### CLI overview

```
python3 ping_standalone_nodes.py \
  --role relay|leaf \
  --use-quic \
  --listen /ip4/0.0.0.0/tcp/41000 \
  --bootstrap /ip4/<host>/tcp/41000/p2p/<PEER_ID> \
  --target /ip4/<host>/tcp/41001/p2p/<PEER_ID> \
  --force-hop \
  --seed <64-hex-chars> | --seed-phrase "<text>" \
  --profile /path/to/profile.json \
  --encrypt-to-prekey-bundle-file /path/to/recipient.bundle.json
```

Omit `--listen` to fall back to `/ip4/127.0.0.1/tcp/41000` (or the QUIC variant
when `--use-quic` is set). The stdin prompt accepts payloads until you send an
empty line or `/quit`.

### Deterministic relay + peers

1. Start the relay (records PUBLIC AutoNAT, restarts with hop):
   ```bash
   python3 ping_standalone_nodes.py \
     --role relay \
     --listen /ip4/0.0.0.0/tcp/41000 \
     --seed-phrase relay-one
   ```
   Note the printed `Local PeerId` (`<RELAY_ID>`).

2. Start peer A through the relay:
   ```bash
   python3 ping_standalone_nodes.py \
     --listen /ip4/0.0.0.0/tcp/41001 \
     --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> \
     --seed-phrase peer-a
   ```

3. Start peer B the same way (different seed phrase):
   ```bash
   python3 ping_standalone_nodes.py \
     --listen /ip4/0.0.0.0/tcp/41002 \
     --bootstrap /ip4/<relay-ip>/tcp/41000/p2p/<RELAY_ID> \
     --seed-phrase peer-b
   ```

Once both peers dial the relay they can exchange payloads interactively via
stdin. Non-interactive environments keep receiving until Ctrl+C.

### Automated localhost mesh

For a quick smoke test with one relay and two leaf peers on the same machine use
`run_local_mesh.sh`:

```bash
cd c-abi-libp2p/examples/python
./run_local_mesh.sh
```

The script performs the following steps:

1. starts a relay on `127.0.0.1:41000`, notes its `PeerId` and exposes the
   address as a bootstrap entry;
2. starts leaf **B** on `127.0.0.1:41002`, dials the relay and stays in a
   receive-only loop;
3. starts leaf **A** on `127.0.0.1:41001`, publishes a scripted payload via
   `--message`, then waits a few seconds before shutting down.

When `E2EE_MODE=on`, the same flow runs with strict libsignal auto E2EE:

1. leaf **B** creates/loads a profile and exports a signed prekey bundle;
2. leaf **A** sends via `--profile + --encrypt-to-prekey-bundle-file`;
3. leaf **B** auto-decrypts and logs `Received prekey payload: ...`.

All stdout/stderr goes to `examples/python/logs/local_mesh/{relay,leafA,leafB}.log`.
Check those files to inspect the mesh behaviour or to attach the logs to reports.

Environment knobs:

```bash
MESSAGE="custom payload" ./run_local_mesh.sh          # change payload
RELAY_PORT=42000 LEAF_A_PORT=42001 LEAF_B_PORT=42002 ./run_local_mesh.sh
TRANSPORT=quic ./run_local_mesh.sh                    # run over QUIC (uses udp/..../quic-v1)
PYTHON_BIN=/path/to/python ./run_local_mesh.sh        # override interpreter
E2EE_MODE=on ./run_local_mesh.sh                      # strict libsignal auto smoke
```

> **Note:** `run_local_mesh.sh` is intended only for single-host smoke tests.
> For a realistic deployment run the three `ping_standalone_nodes.py` commands
> on separate machines using their public IPs/DNS as described above.

## `fidonext_terminal_client.py`

`fidonext_terminal_client.py` is a thin user-facing wrapper over
`ping_standalone_nodes.py` with explicit subcommands:

```bash
python3 fidonext_terminal_client.py relay --listen /ip4/0.0.0.0/tcp/41000
python3 fidonext_terminal_client.py leaf --listen /ip4/0.0.0.0/tcp/41001 --bootstrap /ip4/<host>/tcp/41000/p2p/<RELAY_ID>
```

All extra flags are forwarded to the underlying standalone node CLI.

## `fidonext_chat_client.py` (stateful terminal chats)

`fidonext_chat_client.py` is an interactive terminal chat client with local
identity registration and persistent chat/contact state.

### What it does

- creates/loads local identity from `--profile`
- prints shareable node address (`<listen>/p2p/<peer_id>`)
- persists contacts/chats in a local state file
- publishes/refreshes own DHT directory card (`peer_id + account_id + address`)
- resolves peer by unique id from DHT (`/lookup`, `/connectid`)
- supports simple chat commands (`/contacts`, `/chats`, `/chat use`, `/send`)
- supports optional per-contact libsignal encryption using recipient prekey
  bundle file (`/contact bundle <peer> <bundle.json>`)

### Run

```bash
cd c-abi-libp2p/examples/python
python3 fidonext_chat_client.py \
  --profile ./alice.profile.json \
  --listen /ip4/0.0.0.0/tcp/41001
```

Then in another terminal:

```bash
python3 fidonext_chat_client.py \
  --profile ./bob.profile.json \
  --listen /ip4/0.0.0.0/tcp/41002 \
  --bootstrap /ip4/127.0.0.1/tcp/41001/p2p/<ALICE_PEER_ID>
```

In the chat REPL use `/help` to see all commands.

### Global relay-backed topology (different countries / servers)

1. Deploy several relay containers on separate servers/ASNs/countries and note
   each relay address:
   `/ip4/<relay-ip>/tcp/41000/p2p/<RELAY_PEER_ID>`.
2. Create a bootstrap file on each client (same list on all nodes), for example:

```text
# bootstrap_global.txt
/ip4/203.0.113.10/tcp/41000/p2p/12D3KooW...
/ip4/198.51.100.23/tcp/41000/p2p/12D3KooX...
/ip4/192.0.2.45/tcp/41000/p2p/12D3KooY...
```

3. Start each terminal client with this bootstrap set:

```bash
python3 fidonext_chat_client.py \
  --profile ./alice.profile.json \
  --listen /ip4/0.0.0.0/tcp/41001 \
  --bootstrap-file ./bootstrap_global.txt
```

4. In REPL:
   - `/id` -> share current `PeerId` (current unique network identifier)
   - `/connectid <peer_id>` -> lookup + connect by identifier
   - `/chat use <peer_id>` and `/send <text>` -> chat in terminal

If direct path is unavailable (NAT/firewall), connectivity still works when
both peers maintain connectivity to common relay/bootstrap nodes.

### Native Rust E2EE smoke test

If you want a non-Python smoke test that uses the Rust code path directly, run:

```bash
cd c-abi-libp2p
cargo run --example e2ee_local_mesh
```

The example starts relay + 2 leaf peers, sends one prekey-encrypted message,
then one session-encrypted message, and verifies replay protection.
The source lives in `examples/rust/e2ee_local_mesh.rs`.

## Docker Example (Standalone Nodes)

To run two separate nodes in Docker containers that communicate over a bridge network:

1. Navigate to the python examples directory:
   ```bash
   cd c-abi-libp2p/examples/python
   ```

2. Run with Docker Compose:
   ```bash
   docker-compose up --build
   ```

   This will:
   - Build the Rust library in a Docker container.
   - Create two containers: `libp2p-listener` (at 172.28.0.2) and `libp2p-dialer` (at 172.28.0.3).
   - The dialer will connect to the listener and exchange pings.

   You can see the output of both containers in the terminal. Use Ctrl+C to stop.
