#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ping_example {

constexpr int CABI_STATUS_SUCCESS = 0;
constexpr int CABI_STATUS_NULL_POINTER = 1;
constexpr int CABI_STATUS_INVALID_ARGUMENT = 2;
constexpr int CABI_STATUS_INTERNAL_ERROR = 3;
constexpr int CABI_STATUS_QUEUE_EMPTY = -1;
constexpr int CABI_STATUS_BUFFER_TOO_SMALL = -2;
constexpr int CABI_STATUS_TIMEOUT = 6;
constexpr int CABI_STATUS_NOT_FOUND = 7;

constexpr int CABI_AUTONAT_UNKNOWN = 0;
constexpr int CABI_AUTONAT_PRIVATE = 1;
constexpr int CABI_AUTONAT_PUBLIC = 2;

using InitTracingFunc = int (*)();
using NewNodeFunc = void* (*)(
  bool useQuic,
  bool enableRelayHop,
  const char* const* bootstrapPeers,
  size_t bootstrapPeersLen,
  const uint8_t* identitySeedPtr,
  size_t identitySeedLen);
using NewNodeV2Func = void* (*)(
  bool useQuic,
  bool useWebsocket,
  bool enableRelayHop,
  const char* const* bootstrapPeers,
  size_t bootstrapPeersLen,
  const uint8_t* identitySeedPtr,
  size_t identitySeedLen);
using ReserveRelayFunc = int (*)(void* handle, const char* multiaddr);
using ListenNodeFunc = int (*)(void* handle, const char* multiaddr);
using DialNodeFunc = int (*)(void* handle, const char* multiaddr);
using AutonatStatusFunc = int (*)(void* handle);
using EnqueueMessageFunc = int (*)(void* handle, const uint8_t* dataPtr, size_t dataLen);
using DequeueMessageFunc = int (*)(void* handle, uint8_t* outBuffer, size_t bufferLen, size_t* writtenLen);
using GetAddrsSnapshotFunc = int (*)(void* handle, uint64_t* outVersion, char* outBuf, size_t outBufLen, size_t* outWritten);
using LocalPeerIdFunc = int (*)(void* handle, char* outBuffer, size_t bufferLen, size_t* writtenLen);
using FreeNodeFunc = void (*)(void* handle);

struct CabiRustLibp2p {
  /// Initializes Rust-side tracing/logging in debug-oriented sessions.
  InitTracingFunc InitTracing{};
  /// Creates a node using v1 constructor (QUIC + relay hop options).
  NewNodeFunc NewNode{};
  /// Creates a node using v2 constructor (adds WebSocket toggle).
  NewNodeV2Func NewNodeV2{};
  /// Tries to reserve a relay slot on the provided relay multiaddr.
  ReserveRelayFunc ReserveRelay{};
  /// Starts listening on a local multiaddr.
  ListenNodeFunc ListenNode{};
  /// Dials a remote peer multiaddr.
  DialNodeFunc DialNode{};
  /// Returns current AutoNAT status for this node.
  AutonatStatusFunc AutonatStatus{};
  /// Enqueues a payload into the outbound gossipsub bridge.
  EnqueueMessageFunc EnqueueMessage{};
  /// Dequeues an inbound payload from the node queue.
  DequeueMessageFunc DequeueMessage{};
  /// Reads current listen-address snapshot JSON and version.
  GetAddrsSnapshotFunc GetAddrsSnapshot{};
  /// Returns local peer id string for the node.
  LocalPeerIdFunc LocalPeerId{};
  /// Releases node resources allocated on Rust side.
  FreeNodeFunc FreeNode{};
};

enum class Role {
  Relay,
  Leaf,
};

struct Arguments {
  Role role = Role::Leaf;
  bool useQuic = false;
  bool useWebsocket = false;
  bool forceHop = false;
  std::string listen;
  std::vector<std::string> bootstrapPeers{};
  std::vector<std::string> targetPeers{};
  std::optional<std::array<uint8_t, 32>> identitySeed{};
};

/// Converts C-ABI status codes to human-readable diagnostic text.
std::string statusMessage(int status);

struct NodeHandle {
  void* handle = nullptr;
  const CabiRustLibp2p* abi = nullptr;

  /// Frees current node (if any) and optionally stores a replacement handle.
  void reset(void* newHandle = nullptr);
  /// RAII cleanup that releases the owned node handle on destruction.
  ~NodeHandle();
};

} // namespace ping_example
