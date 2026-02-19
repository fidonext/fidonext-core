#include "ping_app.h"

#include "dyn_lib.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace ping_example {

namespace {

// Converts std::string addresses to C-string pointers expected by the ABI.
std::vector<const char*> toCStrVector(const std::vector<std::string>& values)
{
  std::vector<const char*> result;
  result.reserve(values.size());
  for (const auto& value : values)
  {
    result.push_back(value.c_str());
  }
  return result;
}

// Creates a node using the ABI and applies optional deterministic identity seed.
void* createNode(
  const CabiRustLibp2p& abi,
  const bool useQuic,
  const bool enableRelayHop,
  const std::vector<std::string>& bootstrapPeers,
  const std::optional<std::array<uint8_t, 32>>& seed)
{
  auto bootstrapPtrs = toCStrVector(bootstrapPeers);

  const uint8_t* seedPtr = nullptr;
  size_t seedLen = 0;
  std::array<uint8_t, 32> seedStorage{};

  if (seed.has_value())
  {
    seedStorage = seed.value();
    seedPtr = seedStorage.data();
    seedLen = seedStorage.size();
  }

  void* node = abi.NewNode(useQuic, enableRelayHop, bootstrapPtrs.data(), bootstrapPtrs.size(), seedPtr, seedLen);
  if (!node)
  {
    throw std::runtime_error("failed to create node; see Rust logs for details");
  }
  return node;
}

// Reads local PeerId and resizes the output buffer if ABI reports it is too small.
std::string readPeerId(const CabiRustLibp2p& abi, void* node)
{
  std::vector<char> buffer(128);
  size_t written = 0;
  const int status = abi.LocalPeerId(node, buffer.data(), buffer.size(), &written);

  if (status == CABI_STATUS_BUFFER_TOO_SMALL)
  {
    buffer.resize(written + 1);
    const int retry = abi.LocalPeerId(node, buffer.data(), buffer.size(), &written);
    if (retry != CABI_STATUS_SUCCESS)
    {
      throw std::runtime_error("failed to read peer id: " + statusMessage(retry));
    }
  }
  else if (status != CABI_STATUS_SUCCESS)
  {
    throw std::runtime_error("failed to read peer id: " + statusMessage(status));
  }

  return {buffer.data(), written};
}

// Polls AutoNAT until node becomes PUBLIC or timeout is reached.
bool waitForPublicAutonat(const CabiRustLibp2p& abi, void* node, const std::chrono::seconds timeout)
{
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < timeout)
  {
    const int status = abi.AutonatStatus(node);
    if (status == CABI_AUTONAT_PUBLIC)
    {
      return true;
    }

    if (status == CABI_AUTONAT_PRIVATE)
    {
      std::cout << "AutoNAT: private\n";
    }
    else if (status == CABI_AUTONAT_UNKNOWN)
    {
      std::cout << "AutoNAT: unknown\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return false;
}

// Reads and prints the latest local address snapshot from the node.
void getAddrsSnapshot(const CabiRustLibp2p& abi, void* node)
{
  std::vector<char> buffer(256);
  uint64_t version = 0;

  while (true)
  {
    size_t written = 0;
    const auto status = abi.GetAddrsSnapshot(node, &version, buffer.data(), buffer.size(), &written);
    if (status == CABI_STATUS_SUCCESS)
    {
      const std::string snapshot(buffer.data(), written);
      std::cout << "Addr snapshot v" << version << ":\n";
      std::cout << (snapshot.empty() ? "(empty)\n" : snapshot + "\n");
      break;
    }

    if (status == CABI_STATUS_BUFFER_TOO_SMALL)
    {
      buffer.resize(std::max(buffer.size() * 2, written + 1));
      continue;
    }

    std::cerr << "Failed to read addr snapshot: " << statusMessage(status) << "\n";
    break;
  }
}

// Background receive loop that polls the ABI queue and prints payloads.
void recvLoop(const CabiRustLibp2p& abi, void* node, std::atomic<bool>& keepRunning)
{
  std::vector<uint8_t> buffer(1024);

  while (keepRunning.load(std::memory_order_acquire))
  {
    size_t written = 0;
    const int recvStatus = abi.DequeueMessage(node, buffer.data(), buffer.size(), &written);

    if (recvStatus == CABI_STATUS_SUCCESS)
    {
      std::cout << "Received payload: '"
                << std::string(reinterpret_cast<const char*>(buffer.data()), written)
                << "'\n";
      continue;
    }

    if (recvStatus == CABI_STATUS_QUEUE_EMPTY)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    if (recvStatus == CABI_STATUS_BUFFER_TOO_SMALL)
    {
      const auto newSize = std::max(buffer.size() * 2, written);
      buffer.resize(newSize);
      std::cerr << "Resized receive buffer to " << newSize << " bytes\n";
      continue;
    }

    std::cerr << "Failed to dequeue message: " << statusMessage(recvStatus) << "\n";
    keepRunning.store(false, std::memory_order_release);
    break;
  }
}

// Foreground send loop that reads stdin and forwards messages through the ABI.
void sendLoop(const CabiRustLibp2p& abi, void* node, std::atomic<bool>& keepRunning)
{
  std::cout << "Enter payload (empty line or /quit to exit):\n";
  std::cout << "Enter /addrs to read your address snapshot\n";

  std::string line;
  while (keepRunning.load(std::memory_order_acquire) && std::getline(std::cin, line))
  {
    if (line.empty() || line == "/quit")
    {
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    if (line == "/addrs")
    {
      getAddrsSnapshot(abi, node);
    }

    const int sendStatus = abi.EnqueueMessage(node, reinterpret_cast<const uint8_t*>(line.data()), line.size());
    if (sendStatus != CABI_STATUS_SUCCESS)
    {
      std::cerr << "Failed to send message: " << statusMessage(sendStatus) << "\n";
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    std::cout << "Enter payload (empty line or /quit to exit):\n";
  }
}

// Dials all peer multiaddrs in the provided list and logs per-peer result.
void dialPeers(const CabiRustLibp2p& abi, void* node, const std::vector<std::string>& peers, const char* label)
{
  for (const auto& addr : peers)
  {
    const int status = abi.DialNode(node, addr.c_str());
    if (status == CABI_STATUS_SUCCESS)
    {
      std::cout << "Dialed " << label << " peer: " << addr << "\n";
    }
    else
    {
      std::cerr << "Failed to dial " << label << " peer " << addr << " : " << statusMessage(status) << "\n";
    }
  }
}

// Requests relay reservations on bootstrap relays when node is not publicly reachable.
void reserveOnRelays(const CabiRustLibp2p& abi, void* node, const std::vector<std::string>& peers)
{
  for (const auto& addr : peers)
  {
    const int status = abi.ReserveRelay(node, addr.c_str());
    if (status == CABI_STATUS_SUCCESS)
    {
      std::cout << "Reserved relay on " << addr << "\n";
    }
    else
    {
      std::cerr << "Failed to reserve relay on " << addr << " : " << statusMessage(status) << "\n";
    }
  }
}

} // namespace

// Resolves all required C-ABI function pointers from the loaded shared library.
bool loadAbi(const DynamicLibrary& library, CabiRustLibp2p& abi)
{
  abi.InitTracing = reinterpret_cast<InitTracingFunc>(library.symbol("cabi_init_tracing"));
  abi.NewNode = reinterpret_cast<NewNodeFunc>(library.symbol("cabi_node_new"));
  abi.ReserveRelay = reinterpret_cast<ReserveRelayFunc>(library.symbol("cabi_node_reserve_relay"));
  abi.ListenNode = reinterpret_cast<ListenNodeFunc>(library.symbol("cabi_node_listen"));
  abi.DialNode = reinterpret_cast<DialNodeFunc>(library.symbol("cabi_node_dial"));
  abi.AutonatStatus = reinterpret_cast<AutonatStatusFunc>(library.symbol("cabi_autonat_status"));
  abi.EnqueueMessage = reinterpret_cast<EnqueueMessageFunc>(library.symbol("cabi_node_enqueue_message"));
  abi.DequeueMessage = reinterpret_cast<DequeueMessageFunc>(library.symbol("cabi_node_dequeue_message"));
  abi.GetAddrsSnapshot = reinterpret_cast<GetAddrsSnapshotFunc>(library.symbol("cabi_node_get_addrs_snapshot"));
  abi.LocalPeerId = reinterpret_cast<LocalPeerIdFunc>(library.symbol("cabi_node_local_peer_id"));
  abi.FreeNode = reinterpret_cast<FreeNodeFunc>(library.symbol("cabi_node_free"));

  return abi.InitTracing && abi.NewNode && abi.ListenNode && abi.DialNode && abi.AutonatStatus && abi.EnqueueMessage &&
         abi.DequeueMessage && abi.GetAddrsSnapshot && abi.LocalPeerId && abi.FreeNode;
}

// Runs the whole demo scenario.
// Pipeline for clarity (example-oriented flow):
// 1) create node and print local PeerId,
// 2) start listening on requested address,
// 3) if relay role: wait AutoNAT and optionally restart with hop,
// 4) dial bootstrap and target peers,
// 5) run receive thread + interactive send loop.
int runPingApp(const CabiRustLibp2p& abi, const Arguments& args)
{
  NodeHandle node;
  node.abi = &abi;
  std::atomic<bool> keepRunning(true);

  // Step 1. Create node and print PeerId.
  node.reset(createNode(abi, args.useQuic, false, args.bootstrapPeers, args.identitySeed));
  std::cout << "Local PeerId: " << readPeerId(abi, node.handle) << "\n";

  // Step 2. Start listening.
  int status = abi.ListenNode(node.handle, args.listen.c_str());
  std::cout << "Listening on " << args.listen << "\n";
  if (status != CABI_STATUS_SUCCESS)
  {
    throw std::runtime_error("cabi_node_listen failed: " + statusMessage(status));
  }

  // Step 3. Relay-specific behavior.
  if (args.role == Role::Relay)
  {
    if (args.forceHop)
    {
      std::cout << "Force hop enabled; skipping AutoNAT wait\n";
    }
    else
    {
      constexpr std::chrono::seconds waitTime(10);
      std::cout << "Waiting up to " << waitTime.count()
                << "s for PUBLIC AutoNAT status before enabling relay hop...\n";

      if (waitForPublicAutonat(abi, node.handle, waitTime))
      {
        std::cout << "AutoNAT is PUBLIC; restarting with relay hop enabled\n";
        node.reset(createNode(abi, args.useQuic, true, args.bootstrapPeers, args.identitySeed));

        status = abi.ListenNode(node.handle, args.listen.c_str());
        std::cout << "Listening with hop relay on " << args.listen << "\n";
        if (status != CABI_STATUS_SUCCESS)
        {
          throw std::runtime_error("cabi_node_listen failed after hop restart: " + statusMessage(status));
        }
        std::cout << "Local PeerId: " << readPeerId(abi, node.handle) << "\n";
      }
      else
      {
        std::cout << "AutoNAT did not report PUBLIC within window; staying without hop\n";
        reserveOnRelays(abi, node.handle, args.bootstrapPeers);
      }
    }
  }

  // Step 4. Dial known peers.
  dialPeers(abi, node.handle, args.bootstrapPeers, "bootstrap");
  dialPeers(abi, node.handle, args.targetPeers, "target");

  // Step 5. Run interactive messaging loops.
  std::thread receiver(recvLoop, std::cref(abi), node.handle, std::ref(keepRunning));
  sendLoop(abi, node.handle, keepRunning);
  keepRunning.store(false, std::memory_order_release);
  receiver.join();

  return 0;
}

} // namespace ping_example
