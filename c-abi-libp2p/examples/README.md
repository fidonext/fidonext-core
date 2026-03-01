# ABI usage examples

The `examples/` directory contains minimal snippets that demonstrate how
to load the compiled `libcabi_rust_libp2p` shared library and control
Fidonext nodes from other languages. Each language should live in its
own folder (`python/`, `swift/`, `csharp/`, ...).

Currently we ship:

- `examples/python/` - C-ABI Python client/mesh examples, including
  `fidonext_chat_client.py` for stateful terminal chats.
- `examples/rust/e2ee_local_mesh.rs` - native Rust smoke test for relay + 2 leaf
  peers with strict libsignal auto E2EE, session progression, and replay
  protection.
- `deploy/relay/` - containerized relay deployment assets (`Dockerfile`,
  `docker-compose.yml`, entrypoint, and server runbook).

Run the Rust smoke test from `c-abi-libp2p/`:

```bash
cargo run --example e2ee_local_mesh
```

