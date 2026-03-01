# FidoNext — Decentralized, Private, Open Communication Layer

FidoNext is a next-generation, censorship-resistant communication ecosystem built on top of a fully decentralized mesh of nodes.
No company. No servers. No phone numbers. No identity extraction.
Just pure, resilient communication — owned by people, not corporations.

FidoNext is inspired by the spirit of early decentralized networks (like FidoNET) but re-imagined for the modern world using state-of-the-art cryptography, libp2p, real-time routing, and a trust-agnostic peer-to-peer overlay.

> **FidoNext is an open, community-driven protocol for private human communication.**

## Vision

Modern messaging is centralized, surveilled, profiled and algorithmically controlled.
FidoNext aims to restore digital freedom and build a communication network that:

- Cannot be censored
- Cannot be monitored
- Cannot be owned by governments or corporations
- Cannot be shut down
- Has no servers and no single point of failure
- Is completely independent from DNS, cloud providers, and mobile operators

## Core Principles

### 1. Decentralization
FidoNext is not a service — it's a distributed protocol.
Every user running the app becomes a node in a global communication mesh.

### 2. End-to-end privacy
- Signal-grade cryptography (Double Ratchet + X3DH)
- Zero-knowledge metadata
- Onion-style routing
- Ephemeral relays

### 3. No identity extraction
- No phone numbers
- No emails
- No KYC
- No centralized identity verification
- Local, private key-based identity only

### 4. Resilience and censorship-resistance
- libp2p relay mesh
- Automatic NAT traversal
- Multi-path routing
- Self-healing network architecture

### 5. Open-source, community-owned
The project is fully open and driven by contributors.
There is no “company” behind FidoNext — only the protocol and the community.

## Phoenix Protocol

**Phoenix Protocol** — a decentralized, real-time encrypted messaging protocol built on top of libp2p.

Key elements:

- Decentralized message relay mesh
- Encrypted peer identity layer
- Secure channel establishment
- DHT-based peer discovery
- Circuit-Relay v2 routing
- Optional mixnet-style anonymization
- Metadata-minimized communication flows

## FidoNext App

The FidoNext messenger provides:

- One-tap identity creation
- Real-time encrypted chat
- Encrypted channels and groups
- Public communities
- Zero telemetry
- No phone number or email required
- P2P user discovery
- Multi-relay routing
- Offline message caching

## Current Implementation Status

This repository currently ships the low-level networking/E2EE core in
`c-abi-libp2p/` (Rust + C-ABI + Python examples).

- Messaging transport: `libp2p` (gossipsub + Kademlia DHT).
- End-to-end encryption: official `libsignal` runtime path for auto messaging.
- Auto E2EE mode is strict: message establishment/decryption requires
  `libsignal` prekey bundle fields (legacy explicit prekey/session auto path is
  disabled).
- Single-device delivery mode: each profile/device is currently treated as an
  independent peer endpoint.
- Smoke coverage:
  - Rust local mesh: `cargo run --example e2ee_local_mesh`
  - Python local mesh: `E2EE_MODE=on bash c-abi-libp2p/examples/python/run_local_mesh.sh`
- Protocol drafts:
  - Relay policy + offline mailbox: `c-abi-libp2p/docs/relay-policy-offline-mailbox-spec.md`

## Repository Structure

/protocol/ — Phoenix Protocol specification & research
/core/ — Core networking layer (libp2p, identity, routing)
/apps/ — Desktop & mobile clients
/sdk/ — Developer SDK for building on top of Phoenix Protocol
/docs/ — Documentation & guides

## Contributing

We welcome contributions from developers, researchers, cryptographers, designers, and privacy enthusiasts.

### We are especially looking for:

Rust developers
Mobile engineers
Cryptography engineers
Protocol researchers
UI/UX designers

## Getting Started

git clone https://github.com/fidonext/fidonext-core.git

cd core
cargo build

cargo run

## License

FidoNext is fully open-source under the AGPL-3.0 license.

## Summary

FidoNext is a decentralized, censorship-resistant, privacy-first communication ecosystem.
Not a company. Not a product. A protocol.
A next-generation communication layer owned by the people.

Official website: https://fidonext.org/

Reddit: https://www.reddit.com/r/FidoNext/

For general questions and suggestions: dev@fidonext.org  