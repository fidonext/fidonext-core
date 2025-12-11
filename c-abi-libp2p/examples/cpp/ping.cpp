#include <iostream>
#include <cerrno>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <stdexcept>
#include <vector>

// Crossplatform
#ifdef _WIN32
#include <windows.h>
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

// Basic IP address for the two peers
constexpr const char* CLIENT_IP_ADDR = "127.0.0.1";

using InitTracingFunc = int (*)();
using NewNodeFunc = void* (*)(bool useQuic);
using NewNodeWithRelayFunc = void* (*)(bool useQuic, bool enableRelayHop);
using ListenNodeFunc = int (*)(void* handle, const char* multiaddr);
using DialNodeFunc = int (*)(void* handle, const char* multiaddr);
using AutonatStatusFunc = int (*)(void* handle);
using EnqueueMessageFunc = int (*)(void* handle, const uint8_t* data_ptr, size_t data_len);
using DequeueMessageFunc = int (*)(void* handle, uint8_t* out_buffer, size_t buffer_len, size_t* written_len);
using FreeNodeFunc = void (*)(void* handle);

struct CabiRustLibp2p
{
  InitTracingFunc       InitTracing{};
  NewNodeFunc           NewNode{};
  NewNodeWithRelayFunc  NewNodeWithRelay{};
  ListenNodeFunc        ListenNode{};
  DialNodeFunc          DialNode{};
  AutonatStatusFunc     AutonatStatus{};
  EnqueueMessageFunc    EnqueueMessage{};
  DequeueMessageFunc    DequeueMessage{};
  FreeNodeFunc          FreeNode{};
};

struct Arguments
{
  bool    useQuic       = false;
  string  dialPort    = "41001";
  string  listenPort  = "41000";
  std::vector<string> bootstrapPeers{};
};

bool loadAbi(LibHandle lib, CabiRustLibp2p& abi)
{
  abi.InitTracing = reinterpret_cast<InitTracingFunc>(GET_PROC(lib, "cabi_init_tracing"));
  abi.NewNode = reinterpret_cast<NewNodeFunc>(GET_PROC(lib, "cabi_node_new"));
  abi.NewNodeWithRelay = reinterpret_cast<NewNodeWithRelayFunc>(GET_PROC(lib, "cabi_node_new_with_relay"));
  abi.ListenNode = reinterpret_cast<ListenNodeFunc>(GET_PROC(lib, "cabi_node_listen"));
  abi.DialNode = reinterpret_cast<DialNodeFunc>(GET_PROC(lib, "cabi_node_dial"));
  abi.AutonatStatus = reinterpret_cast<AutonatStatusFunc>(GET_PROC(lib, "cabi_autonat_status"));
  abi.EnqueueMessage = reinterpret_cast<EnqueueMessageFunc>(GET_PROC(lib, "cabi_node_enqueue_message"));
  abi.DequeueMessage = reinterpret_cast<DequeueMessageFunc>(GET_PROC(lib, "cabi_node_dequeue_message"));
  abi.FreeNode = reinterpret_cast<FreeNodeFunc>(GET_PROC(lib, "cabi_node_free"));

  return  abi.InitTracing && abi.NewNode && abi.NewNodeWithRelay &&
          abi.ListenNode && abi.DialNode && abi.AutonatStatus && 
          abi.EnqueueMessage && abi.DequeueMessage && abi.FreeNode;
}

Arguments parseArgs(int argc, char** argv)
{
  Arguments args;

  for (int i = 1; i < argc; ++i)
  {
    const string arg = argv[i];

    if (arg == "--use-quic")
    {
      args.useQuic = true;
    }
    else if (arg == "--lport" && i + 1 < argc)
    {
      args.listenPort = argv[++i];
    }
    else if (arg == "--dport" && i + 1 < argc)
    {
      args.dialPort = argv[++i];
    }
    else if (arg == "--bootstrap" && i + 1 < argc)
    {
      args.bootstrapPeers.emplace_back(argv[++i]);
    }
    else if (arg == "--help" || arg == "-h")
    {
      cout << "Usage: ping [--use-quic] [--lport <int>] [--dport <int>]"
           << " [--bootstrap <multiaddr>]...\n";
      std::exit(0);
    }
    else
    {
      cerr << "Unknown argument: " << arg << "\n";
      std::exit(1);
    }
  }

  return args;
}

string toMultiaddr(const string& port, bool useQuic)
{
  if (useQuic)
  {
    return "/ip4/127.0.0.1/udp/" + port + "/quic-v1";
  }

  return "/ip4/127.0.0.1/tcp/" + port;
}

string statusMessage(int status)
{
  switch (status)
  {
  case CABI_STATUS_SUCCESS:
    return "0k";
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

void* createNode(const CabiRustLibp2p& abi, bool useQuic, bool enableRelayHop)
{
  void* node = enableRelayHop
    ? abi.NewNodeWithRelay(useQuic, true)
    : abi.NewNode(useQuic);

  if (!node)
  {
    throw std::runtime_error("failed to create node; see Rust logs");
  }

  return node;
}

void dialBootstraps(const CabiRustLibp2p& abi, void* node, 
  const std::vector<string>& bootstrapPeers)
{
  for (const auto& bootstrap : bootstrapPeers)
  {
    cout << "Dialing bootstrap peer: " << bootstrap << "\n";
    const int status = abi.DialNode(node, bootstrap.c_str());
    if (status != CABI_STATUS_SUCCESS)
    {
      cerr << "Failed to dial bootstrap peer (" << bootstrap << "): "
            << statusMessage(status) << "\n";
    }
  }
}

bool waitForPublicAutonat(const CabiRustLibp2p& abi, void* node, std::chrono::seconds timeout)
{
  auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < timeout)
  {
    const int status = abi.AutonatStatus(node);
    if (status == CABI_AUTONAT_PUBLIC)
    {
      return true;
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  return false;
}

void receiveLoop(
  const CabiRustLibp2p& abi,
  void* node,
  std::atomic<bool>& keepRunning)
{
  std::vector<uint8_t> buffer(1024);

  while (keepRunning.load(std::memory_order_acquire))
  {
    size_t written = 0;
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

    if (recvStatus == CABI_STATUS_QUEUE_EMPTY)
    {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    if (recvStatus == CABI_STATUS_BUFFER_TOO_SMALL)
    {
      cerr << "Incoming payload larger than buffer (" << written
        << " bytes); increase buffer to capture full message\n";
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }

    cerr << "Failed to dequeue message: " << statusMessage(recvStatus) << "\n";
    keepRunning.store(false, std::memory_order_release);
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
    if (line.empty() || line == "/quit")
    {
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    // Enqueue msg in order to sen it
    const auto sendStatus = abi.EnqueueMessage(
      node,
      reinterpret_cast<const uint8_t*>(line.data()),
      line.size());

    if (sendStatus != CABI_STATUS_SUCCESS)
    {
      cerr << "Failed to send message: " << statusMessage(sendStatus) << "\n";
      keepRunning.store(false, std::memory_order_release);
      break;
    }

    cout << "Enter payload (empty line or /quit to exit):\n";
  }
}

int main(int argc, char** argv)
{
  LibHandle lib = LOAD_LIB(LIB_NAME);
  if (!lib)
  {
    cerr << "Error on loading Lib:" << LIB_NAME << "\n";
    return 1;
  }

  // Try get functions from library
  CabiRustLibp2p abi{};
  if (!loadAbi(lib, abi))
  {
    cerr << "Missing required functions in library \n";
    CLOSE_LIB(lib);
    return 1;
  }

  const Arguments args = parseArgs(argc, argv);
  const auto listenerAddr = toMultiaddr(args.listenPort, args.useQuic);
  const auto dialerAddr = toMultiaddr(args.dialPort, args.useQuic);

  // Try init cabi's tracing
  if (abi.InitTracing() != CABI_STATUS_SUCCESS)
  {
    cerr << "Failed to initialize tracing. Continuing without tracing\n";
  }

  try
  {
    // Step 1. Create Node
    void* node = createNode(abi, args.useQuic, false);

    // Step 2. Listen port. Begin Listening
    auto status = abi.ListenNode(node, listenerAddr.c_str());
    cout << "Listening on: " << CLIENT_IP_ADDR << ":" << args.listenPort
      << " (" << listenerAddr << ")\n";
    if (status != CABI_STATUS_SUCCESS)
    {
      abi.FreeNode(node);
      throw std::runtime_error("cabi_node_listen failed: " + statusMessage(status));
    }

    // Start delay, waiting for listener to be ready
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Step 3. Dial bootstrap peers if provided
    dialBootstraps(abi, node, args.bootstrapPeers);

    // Step 4. Check AutoNAT and restart with hop relay if public
    if (waitForPublicAutonat(abi, node, std::chrono::seconds(10)))
    {
      cout << "AutoNAT is public; restarting node with relay hop enabled\n";
      abi.FreeNode(node);

      node = createNode(abi, args.useQuic, true);
      status = abi.ListenNode(node, listenerAddr.c_str());
      cout << "Listening on: " << CLIENT_IP_ADDR << ":" << args.listenPort
        << " (" << listenerAddr << ") [hop relay]\n";
      if (status != CABI_STATUS_SUCCESS)
      {
        abi.FreeNode(node);
        throw std::runtime_error("cabi_node_listen failed after restart: " + statusMessage(status));
      }

      // Start delay, waiting for listener to be ready
      std::this_thread::sleep_for(std::chrono::milliseconds(500));

      dialBootstraps(abi, node, args.bootstrapPeers);
    }

    // Step 5. Dial to other client
    status = abi.DialNode(node, dialerAddr.c_str());
    if (status != CABI_STATUS_SUCCESS)
    {
      abi.FreeNode(node);
      throw std::runtime_error("cabi_node_dial failed: " + statusMessage(status));
    }

    std::atomic<bool> keepRunning = true;

    // Step 6. Start receiving messages from other peer
    std::thread receiver(
      receiveLoop,
      std::cref(abi),
      node,
      std::ref(keepRunning)
    );

    // Step 7. Send the user's payload loop
    sendLoop(abi, node, keepRunning);

    // Stop recv thread
    keepRunning.store(false, std::memory_order_release);
    receiver.join();

    // Step 8. Don't forget to free node
    abi.FreeNode(node);
  }
  catch (const std::exception& ex)
  {
    cerr << "Fatal error: " << ex.what() << "\n";
    CLOSE_LIB(lib);
    return 1;
  }


  CLOSE_LIB(lib);
  return 0;
}
