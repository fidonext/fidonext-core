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
  InitTracingFunc InitTracing{};
  NewNodeFunc NewNode{};
  ReserveRelayFunc ReserveRelay{};
  ListenNodeFunc ListenNode{};
  DialNodeFunc DialNode{};
  AutonatStatusFunc AutonatStatus{};
  EnqueueMessageFunc EnqueueMessage{};
  DequeueMessageFunc DequeueMessage{};
  GetAddrsSnapshotFunc GetAddrsSnapshot{};
  LocalPeerIdFunc LocalPeerId{};
  FreeNodeFunc FreeNode{};
};

enum class Role {
  Relay,
  Leaf,
};

struct Arguments {
  Role role = Role::Leaf;
  bool useQuic = false;
  bool forceHop = false;
  std::string listen;
  std::vector<std::string> bootstrapPeers{};
  std::vector<std::string> targetPeers{};
  std::optional<std::array<uint8_t, 32>> identitySeed{};
};

std::string statusMessage(int status);

struct NodeHandle {
  void* handle = nullptr;
  const CabiRustLibp2p* abi = nullptr;

  void reset(void* newHandle = nullptr);
  ~NodeHandle();
};

} // namespace ping_example