#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <array>
#include <thread>
#include <atomic>

// Crossplatform
#ifdef _WIN32
#include <windows.h>
#undef max
#undef min
using LibHandle = HMODULE;
#define LOAD_LIB(path) LoadLibraryA(path)
#define GET_PROC(lib, name) GetProcAddress(lib, name)
#define CLOSE_LIB(lib) FreeLibrary(lib)
constexpr auto LIB_NAME = "cabi_rust_libp2p.dll";
#else
#include <dlfcn.h>
using LibHandle = void*;
#define LOAD_LIB(path) dlopen(path, RTLD_LAZY)
#define GET_PROC(lib, name) dlsym(lib, name)
#define CLOSE_LIB(lib) dlclose(lib)
constexpr auto LIB_NAME = "./libcabi_rust_libp2p.so";
#endif

using std::cout;
using std::cerr;
using std::string;

// General statuses
// Operation completed successfully.
constexpr int CABI_STATUS_SUCCESS = 0;
// One of the provided pointers was null.
constexpr int CABI_STATUS_NULL_POINTER = 1;
// Invalid argument supplied (e.g. malformed multiaddr).
constexpr int CABI_STATUS_INVALID_ARGUMENT = 2;
// Internal runtime error – check logs for details.
constexpr int CABI_STATUS_INTERNAL_ERROR = 3;

// AutoNAT statuses
// AutoNAT status has not yet been determined.
constexpr int CABI_AUTONAT_UNKNOWN = 0;
// AutoNAT reports the node as privately reachable only.
constexpr int CABI_AUTONAT_PRIVATE = 1;
// AutoNAT reports the node as publicly reachable.
constexpr int CABI_AUTONAT_PUBLIC  = 2;

// Payload statuses
// Queue contains no new messages.
constexpr int CABI_STATUS_QUEUE_EMPTY = 4;
// Provided buffer too small to hold the next message.
constexpr int CABI_STATUS_BUFFER_TOO_SMALL = 5;
// Default capacity for the message queue.
constexpr int DEFAULT_MESSAGE_QUEUE_CAPACITY = 64;

// Address event kinds
constexpr int CABI_ADDR_EVENT_LISTEN_ADDED = 0;
constexpr int CABI_ADDR_EVENT_LISTEN_REMOVED = 1;
constexpr int CABI_ADDR_EVENT_EXTERNAL_CONFIRMED = 2;
constexpr int CABI_ADDR_EVENT_EXTERNAL_EXPIRED = 3;
constexpr int CABI_ADDR_EVENT_RELAY_READY = 4;

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
using EnqueueMessageFunc = int (*)(void* handle, const uint8_t* data_ptr, size_t data_len);
using DequeueMessageFunc = int (*)(void* handle, uint8_t* out_buffer, size_t buffer_len, size_t* written_len);
using DequeueAddrEventFunc = int (*)(void* handle, int* out_kind, char* addr_buf, size_t addr_buf_len, size_t* out_written);
using LocalPeerIdFunc = int (*)(void* handle, char* out_buffer, size_t buffer_len, size_t* written_len);
using FreeNodeFunc = void (*)(void* handle);

struct CabiRustLibp2p
{
  InitTracingFunc       InitTracing{};
  NewNodeFunc           NewNode{};
  ReserveRelayFunc      ReserveRelay{};
  ListenNodeFunc        ListenNode{};
  DialNodeFunc          DialNode{};
  AutonatStatusFunc     AutonatStatus{};
  EnqueueMessageFunc    EnqueueMessage{};
  DequeueMessageFunc    DequeueMessage{};
  DequeueAddrEventFunc  DequeueAddrEvent{};
  LocalPeerIdFunc       LocalPeerId{};
  FreeNodeFunc          FreeNode{};
};

enum class Role
{
  Relay,
  Leaf,
};

struct Arguments
{
  Role role = Role::Leaf;
  bool useQuic = false;
  bool forceHop = false;
  string listen;
  std::vector<string> bootstrapPeers{};
  std::vector<string> targetPeers{};
  std::optional<std::array<uint8_t, 32>> identitySeed{};
};

// RAII for handle of the node
struct NodeHandle
{
  void reset(void* newHandle = nullptr)
  {
    if (handle && abi && abi->FreeNode)
    {
      abi->FreeNode(handle);
    }

    handle = newHandle;
  }

  ~NodeHandle()
  {
    reset();
  }

  void* handle = nullptr;
  const CabiRustLibp2p* abi = nullptr;
};

string statusMessage(int status)
{
  switch (status)
  {
  case CABI_STATUS_SUCCESS:
    return "ok";
  case CABI_STATUS_NULL_POINTER:
    return "Null pointer passed into ABI";
  case CABI_STATUS_INVALID_ARGUMENT:
    return "Invalid argument (multiaddr or UTF-8)";
  case CABI_STATUS_QUEUE_EMPTY:
    return "Queue empty";
  case CABI_STATUS_BUFFER_TOO_SMALL:
    return "Provided buffer too small";
  default:
    return "Internal error - inspect Rust logs for details";
  }
}

bool loadAbi(LibHandle lib, CabiRustLibp2p& abi)
{
  abi.InitTracing = reinterpret_cast<InitTracingFunc>(GET_PROC(lib, "cabi_init_tracing"));
  abi.NewNode = reinterpret_cast<NewNodeFunc>(GET_PROC(lib, "cabi_node_new"));
  abi.ReserveRelay = reinterpret_cast<ReserveRelayFunc>(GET_PROC(lib, "cabi_node_reserve_relay"));
  abi.ListenNode = reinterpret_cast<ListenNodeFunc>(GET_PROC(lib, "cabi_node_listen"));
  abi.DialNode = reinterpret_cast<DialNodeFunc>(GET_PROC(lib, "cabi_node_dial"));
  abi.AutonatStatus = reinterpret_cast<AutonatStatusFunc>(GET_PROC(lib, "cabi_autonat_status"));
  abi.EnqueueMessage = reinterpret_cast<EnqueueMessageFunc>(GET_PROC(lib, "cabi_node_enqueue_message"));
  abi.DequeueMessage = reinterpret_cast<DequeueMessageFunc>(GET_PROC(lib, "cabi_node_dequeue_message"));
  abi.DequeueAddrEvent = reinterpret_cast<DequeueAddrEventFunc>(GET_PROC(lib, "cabi_node_dequeue_addr_event"));
  abi.LocalPeerId = reinterpret_cast<LocalPeerIdFunc>(GET_PROC(lib, "cabi_node_local_peer_id"));
  abi.FreeNode = reinterpret_cast<FreeNodeFunc>(GET_PROC(lib, "cabi_node_free"));

  return  abi.InitTracing && abi.NewNode && abi.ListenNode &&
          abi.DialNode && abi.AutonatStatus && abi.EnqueueMessage &&
          abi.DequeueMessage && abi.DequeueAddrEvent && abi.LocalPeerId &&
          abi.FreeNode;
}

string defaultListen(bool useQuic)
{
  if (useQuic)
  {
    return "/ip4/127.0.0.1/udp/41000/quic-v1";
  }

  return "/ip4/127.0.0.1/tcp/41000";
}

std::array<uint8_t, 32> parseSeed(const string& hexSeed)
{
  if (hexSeed.size() != 64)
  {
    throw std::invalid_argument("seed must contain exactly 64 hex characters (32 bytes)");
  }

  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < 32; ++i)
  {
    const auto byteStr = hexSeed.substr(i * 2, 2);
    char* endPtr = nullptr;
    const auto value = std::strtoul(byteStr.c_str(), &endPtr, 16);
    if (endPtr == byteStr.c_str() || value > 0xFF)
    {
      throw std::invalid_argument("seed contains non-hex characters");
    }
    seed[i] = static_cast<uint8_t>(value);
  }

  return seed;
}

// Simple FNV-1a-inspired mixer across four lanes to fill 32 bytes deterministically.
// This one was needed as it is easier to provide string seed rather 32 len num
std::array<uint8_t, 32> deriveSeedFromString(const string& seedPhrase)
{
  constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
  constexpr uint64_t FNV_PRIME  = 0x100000001b3ULL;

  std::array<uint64_t, 4> lanes{
    FNV_OFFSET ^ 0x736565646c616e65ULL, // "seedlane"
    FNV_OFFSET ^ 0x706872617365313ULL,  // "phrase1"
    FNV_OFFSET ^ 0x706872617365323ULL,  // "phrase2"
    FNV_OFFSET ^ 0x706872617365333ULL,  // "phrase3"
  };

  for (const unsigned char byte : seedPhrase)
  {
    for (size_t i = 0; i < lanes.size(); ++i)
    {
      lanes[i] ^= static_cast<uint64_t>(byte) + (0x9e3779b97f4a7c15ULL * i);
      lanes[i] *= (FNV_PRIME + (i * 2));
      lanes[i] ^= lanes[(i + 1) % lanes.size()] >> (8 * (i + 1));
    }
  }

  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < lanes.size(); ++i)
  {
    const uint64_t value = lanes[i];
    seed[i * 8 + 0] = static_cast<uint8_t>((value >> 0) & 0xFF);
    seed[i * 8 + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    seed[i * 8 + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    seed[i * 8 + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    seed[i * 8 + 4] = static_cast<uint8_t>((value >> 32) & 0xFF);
    seed[i * 8 + 5] = static_cast<uint8_t>((value >> 40) & 0xFF);
    seed[i * 8 + 6] = static_cast<uint8_t>((value >> 48) & 0xFF);
    seed[i * 8 + 7] = static_cast<uint8_t>((value >> 56) & 0xFF);
  }

  return seed;
}

Arguments parseArgs(int argc, char** argv)
{
  Arguments args;
  bool listenProvided = false;
  bool seedProvided = false;

  for (int i = 1; i < argc; ++i)
  {
    const string arg = argv[i];

    if (arg == "--role" && i + 1 < argc)
    {
      const string roleValue = argv[++i];
      if (roleValue == "relay")
      {
        args.role = Role::Relay;
      }
      else if (roleValue == "leaf")
      {
        args.role = Role::Leaf;
      }
      else
      {
        throw std::invalid_argument("--role must be 'relay' or 'leaf'");
      }
    }
    else if (arg == "--use-quic")
    {
      args.useQuic = true;
    }
    else if (arg == "--force-hop")
    {
      args.forceHop = true;
    }
    else if (arg == "--listen" && i + 1 < argc)
    {
      args.listen = argv[++i];
      listenProvided = true;
    }
    else if (arg == "--bootstrap" && i + 1 < argc)
    {
      args.bootstrapPeers.emplace_back(argv[++i]);
    }
    else if (arg == "--target" && i + 1 < argc)
    {
      args.targetPeers.emplace_back(argv[++i]);
    }
        else if (arg == "--seed" && i + 1 < argc)
    {
      if (seedProvided)
      {
        throw std::invalid_argument("--seed/--seed-phrase are mutually exclusive");
      }
      args.identitySeed = parseSeed(argv[++i]);
      seedProvided = true;
    }
    else if (arg == "--seed-phrase" && i + 1 < argc)
    {
      if (seedProvided)
      {
        throw std::invalid_argument("--seed/--seed-phrase are mutually exclusive");
      }
      args.identitySeed = deriveSeedFromString(argv[++i]);
      seedProvided = true;
    }
    else if (arg == "--help" || arg == "-h")
    {
      cout  << "relay_chat usage:\n"
            << "  --role relay|leaf (default: leaf)\n"
            << "  --use-quic\n"
            << "  --listen <multiaddr>\n"
            << "  --bootstrap <multiaddr> (repeatable)\n"
            << "  --force-hop (relay only; start with hop enabled without waiting for AutoNAT)\n"
            << "  --target <multiaddr> (repeatable)\n"
            << "  --seed <64-hex-bytes> (deterministic PeerId)\n"
            << "  --seed-phrase <string> (derive 32-byte seed deterministically)\n";

      std::exit(0);
    }
    else
    {
      throw std::invalid_argument("Unknown argument: " + arg);
    }
  }

  if (!listenProvided)
  {
    args.listen = defaultListen(args.useQuic);
  }

  return args;
}

std::vector<const char*> toCStrVector(const std::vector<string>& values)
{
  std::vector<const char*> result;
  result.reserve(values.size());

  for (const auto& value : values)
  {
    result.push_back(value.c_str());
  }

  return result;
}

void* createNode(
  const CabiRustLibp2p& abi,
  bool useQuic,
  bool enableRelayHop,
  const std::vector<string>& bootstrapPeers,
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

  void* node = abi.NewNode(
    useQuic,
    enableRelayHop,
    bootstrapPtrs.data(),
    bootstrapPtrs.size(),
    seedPtr,
    seedLen);

  if (!node)
  {
    throw std::runtime_error("failed to create node; see Rust logs for details");
  }

  return node;
}

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

  return string(buffer.data(), written);
}

// Get Autonat status in order to have a possibility
// to detect whether it is public or private
bool waitForPublicAutonat(const CabiRustLibp2p& abi, void* node,
  std::chrono::seconds timeout = std::chrono::seconds(10))
{
  auto start = std::chrono::steady_clock::now();

  while (std::chrono::steady_clock::now() - start < timeout)
  {
    const int status = abi.AutonatStatus(node);
    if (status == CABI_AUTONAT_PUBLIC)
    {
      return true;
    }

    if (status == CABI_AUTONAT_PRIVATE)
    {
      cout << "AutoNAT: private\n";
    }
    else if (status == CABI_AUTONAT_UNKNOWN)
    {
      cout << "AutoNAT: unknown\n";
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return false;
}

string addrEventKindLabel(int kind)
{
  switch (kind)
  {
  case CABI_ADDR_EVENT_LISTEN_ADDED:
    return "listen-added";
  case CABI_ADDR_EVENT_LISTEN_REMOVED:
    return "listen-removed";
  case CABI_ADDR_EVENT_EXTERNAL_CONFIRMED:
    return "external-confirmed";
  case CABI_ADDR_EVENT_EXTERNAL_EXPIRED:
    return "external-expired";
  case CABI_ADDR_EVENT_RELAY_READY:
    return "relay-ready";
  default:
    return "unknown";
  }
}

void recvLoop(
  const CabiRustLibp2p& abi,
  void* node,
  std::atomic<bool>& keepRunning)
{
  std::vector<uint8_t> buffer(1024);

  while (keepRunning.load(std::memory_order_acquire))
  {
    size_t written = 0;
    // Here you get the message
    const auto recvStatus = abi.DequeueMessage(
      node,
      buffer.data(),
      buffer.size(),
      &written);

    if (recvStatus == CABI_STATUS_SUCCESS)
    {
      const string payload(
        reinterpret_cast<const char*>(buffer.data()),
        written);
      cout << "Received payload: '" << payload << "'\n";
      continue;
    }

    // Wait a lil bit to reduce rquests
    if (recvStatus == CABI_STATUS_QUEUE_EMPTY)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    // Hadle bufer is to small to recieve payload
    if (recvStatus == CABI_STATUS_BUFFER_TOO_SMALL)
    {
      const auto newSize = std::max(buffer.size() * 2, written);
      buffer.resize(newSize);
      cerr << "Resized receive buffer to " << newSize << " bytes\n";
      continue;
    }

    cerr << "Failed to dequeue message: " << statusMessage(recvStatus) << "\n";
    keepRunning.store(false, std::memory_order_release);
    break;
  }
}

void drainAddrEvents(
  const CabiRustLibp2p& abi,
  void* node)
{
  std::vector<char> buffer(256);

  while (true)
  {
    int kind = 0;
    size_t written = 0;
    const auto status = abi.DequeueAddrEvent(
      node,
      &kind,
      buffer.data(),
      buffer.size(),
      &written);

    if (status == CABI_STATUS_SUCCESS)
    {
      const string addr(buffer.data(), written);
      cout << "Addr event (" << addrEventKindLabel(kind) << "): " << addr << "\n";
      continue;
    }

    if (status == CABI_STATUS_QUEUE_EMPTY)
    {
      break;
    }

    if (status == CABI_STATUS_BUFFER_TOO_SMALL)
    {
      const auto newSize = std::max(buffer.size() * 2, written + 1);
      buffer.resize(newSize);
      cerr << "Resized addr buffer to " << newSize << " bytes\n";
      continue;
    }

    cerr << "Failed to dequeue addr event: " << statusMessage(status) << "\n";
    break;
  }
}

void sendLoop(
  const CabiRustLibp2p& abi,
  void* node,
  std::atomic<bool>& keepRunning)
{
  cout << "Enter payload (empty line or /quit to exit):\n";
  string line;

  while (keepRunning.load(std::memory_order_acquire) && std::getline(std::cin, line))
  {
    // Quit scenario
    if (line.empty() || line == "/quit")
    {
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    // This one sends the payloads
    const auto sendStatus = abi.EnqueueMessage(
      node,
      reinterpret_cast<const uint8_t*>(line.data()),
      line.size());

    // Quit of failing sending message
    if (sendStatus != CABI_STATUS_SUCCESS)
    {
      cerr << "Failed to send message: " << statusMessage(sendStatus) << "\n";
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    cout << "Enter payload (empty line or /quit to exit):\n";
  }
}

// Initital dial to know that peer is enabled
void dialPeers(const CabiRustLibp2p& abi, void* node, const std::vector<string>& peers, const char* label)
{
  for (const auto& addr : peers)
  {
    const auto status = abi.DialNode(node, addr.c_str());
    if (status == CABI_STATUS_SUCCESS)
    {
      cout << "Dialed " << label << " peer: " << addr << "\n";
    }
    else
    {
      cerr << "Failed to dial " << label << " peer " << addr << " : " << statusMessage(status) << "\n";
    }
  }
}

void reserveOnRelays(const CabiRustLibp2p& abi, void* node, const std::vector<string>& peers)
{
  for (const auto& addr : peers)
  {
    const auto status = abi.ReserveRelay(node, addr.c_str());

    if (status == CABI_STATUS_SUCCESS)
    {
      cout << "Reserved relay on " << addr << "\n";
    }
    else
    {
      cerr << "Failed to reserve relay on " << addr << " : " << statusMessage(status) << "\n";
    }
  }
}

int main(int argc, char** argv)
{
  // Step 1. Load lib
  LibHandle lib = LOAD_LIB(LIB_NAME);
  if (!lib)
  {
    cerr << "Error loading lib: " << LIB_NAME << "\n";
    return 1;
  }

  // Step 2. Load functions from lib
  CabiRustLibp2p abi{};
  if (!loadAbi(lib, abi))
  {
    cerr << "Missing required functions in library\n";
    CLOSE_LIB(lib);
    return 1;
  }

  // Step 3. Parse args
  Arguments args;
  try
  {
    args = parseArgs(argc, argv);
  }
  catch (const std::exception& ex)
  {
    cerr << "Argument error: " << ex.what() << "\n";
    CLOSE_LIB(lib);
    return 1;
  }

  #if _DEBUG
  // Optionally init rust's tracing
  if (abi.InitTracing() != CABI_STATUS_SUCCESS)
  {
    cerr << "Failed to initialize tracing. Continuing without tracing\n";
  }
  #endif

  NodeHandle node;
  node.abi = &abi;

  std::atomic<bool> keepRunning(true);

  auto signalHandler = [](int) {
    // no-op placeholder to break getline
  };
  std::signal(SIGINT, signalHandler);

  try
  {
    // Step 4. Create node for this peer
    node.reset(createNode(abi, args.useQuic, false, args.bootstrapPeers, args.identitySeed));
    cout << "Local PeerId: " << readPeerId(abi, node.handle) << "\n";

    // Step 5. Try listen on provided addr
    auto status = abi.ListenNode(node.handle, args.listen.c_str());
    cout << "Listening on " << args.listen << "\n";
    if (status != CABI_STATUS_SUCCESS)
    {
      throw std::runtime_error("cabi_node_listen failed: " + statusMessage(status));
    }

    // Relay node behaviour
    if (args.role == Role::Relay)
    {
      if (args.forceHop)
      {
        cout << "Force hop enabled; skipping AutoNAT wait\n";
      }
      else
      {
        std::chrono::seconds waitTime(10);
        cout << "Waiting up to " << waitTime.count() << "s for PUBLIC AutoNAT status before enabling relay hop...\n";
        
        // Step 6. Try understand wheter node is public or private
        // And if public, remake the node
        if (waitForPublicAutonat(abi, node.handle, waitTime))
        {
          cout << "AutoNAT is PUBLIC; restarting with relay hop enabled\n";
          node.reset();
          node.reset(createNode(abi, args.useQuic, true, args.bootstrapPeers, args.identitySeed));

          status = abi.ListenNode(node.handle, args.listen.c_str());
          cout << "Listening with hop relay on " << args.listen << "\n";
          if (status != CABI_STATUS_SUCCESS)
          {
            throw std::runtime_error("cabi_node_listen failed after hop restart: " + statusMessage(status));
          }
          cout << "Local PeerId: " << readPeerId(abi, node.handle) << "\n";
        }
        else
        {
          cout << "AutoNAT did not report PUBLIC within window; staying without hop\n";
          reserveOnRelays(abi, node.handle, args.bootstrapPeers);
        }
      }
    }

    // Step 7. Initail dial to know active peers from bootstrap and target
    dialPeers(abi, node.handle, args.bootstrapPeers, "bootstrap");
    dialPeers(abi, node.handle, args.targetPeers, "target");

    drainAddrEvents(abi, node.handle);

    std::thread receiver(
      recvLoop,
      std::cref(abi),
      node.handle,
      std::ref(keepRunning));

    // Step 8. Start sending loop
    sendLoop(abi, node.handle, keepRunning);

    keepRunning.store(false, std::memory_order_release);
    receiver.join();
  }
  catch (const std::exception& ex)
  {
    cerr << "Fatal error: " << ex.what() << "\n";
    keepRunning.store(false, std::memory_order_release);
    node.reset();
    CLOSE_LIB(lib);
    return 1;
  }

  node.reset();
  CLOSE_LIB(lib);
  return 0;
}