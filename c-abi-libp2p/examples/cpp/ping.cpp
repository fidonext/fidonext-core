#include <iostream>
#include <cerrno>
#include <string>
#include <thread>
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
constexpr auto LIB_NAME = "cabi_rust_libp2p.so";
#endif

using std::cout;
using std::cerr;
using std::string;

// Operation completed successfully.
constexpr int CABI_STATUS_SUCCESS = 0;
// One of the provided pointers was null.
constexpr int CABI_STATUS_NULL_POINTER = 1;
// Invalid argument supplied (e.g. malformed multiaddr).
constexpr int CABI_STATUS_INVALID_ARGUMENT = 2;
// Internal runtime error – check logs for details.
constexpr int CABI_STATUS_INTERNAL_ERROR = 3;
// Basic IP address for the two peers
constexpr const char* CLIENT_IP_ADDR = "127.0.0.1";

using InitTracingFunc = int (*)();
using NewNodeFunc = void* (*)(bool useQuic);
using ListenNodeFunc = int (*)(void* handle, const char* multiaddr);
using DialNodeFunc = int (*)(void* handle, const char* multiaddr);
using FreeNodeFunc = void (*)(void* handle);

struct CabiRustLibp2p
{
  InitTracingFunc InitTracing{};
  NewNodeFunc     NewNode{};
  ListenNodeFunc  ListenNode{};
  DialNodeFunc    DialNode{};
  FreeNodeFunc    FreeNode{};
};

struct Arguments
{
  bool    useQuic       = false;
  string  dialPort    = "41001";
  string  listenPort  = "41000";
  float   duration      = 10.0f;
  std::vector<string> bootstrapPeers{};
};

bool loadAbi(LibHandle lib, CabiRustLibp2p& abi)
{
  abi.InitTracing = reinterpret_cast<InitTracingFunc>(GET_PROC(lib, "cabi_init_tracing"));
  abi.NewNode = reinterpret_cast<NewNodeFunc>(GET_PROC(lib, "cabi_node_new"));
  abi.ListenNode = reinterpret_cast<ListenNodeFunc>(GET_PROC(lib, "cabi_node_listen"));
  abi.DialNode = reinterpret_cast<DialNodeFunc>(GET_PROC(lib, "cabi_node_dial"));
  abi.FreeNode = reinterpret_cast<FreeNodeFunc>(GET_PROC(lib, "cabi_node_free"));

  return  abi.InitTracing && abi.NewNode &&
          abi.ListenNode && abi.DialNode && abi.FreeNode;
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
    else if (arg == "--duration" && i + 1 < argc)
    {
      args.duration = std::stof(argv[++i]);
    }
    else if (arg == "--bootstrap" && i + 1 < argc)
    {
      args.bootstrapPeers.emplace_back(argv[++i]);
    }
    else if (arg == "--help" || arg == "-h")
    {
      cout << "Usage: ping [--use-quic] [--lport <int>] [--dport <int>] [--duration <seconds>]"
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
  default:
    return "Internal error – inspect Rust logs for details";
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
    cerr << "Failed to initialize trcing. Continuing without tracing\n";
  }

  try
  {
    // Step 1. Create Node
    void* node = abi.NewNode(args.useQuic);
    if (!node)
    {
      throw std::runtime_error("cabi_node_new returned NULL, check Rust logs");
    }


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
    for (const auto& bootstrap : args.bootstrapPeers)
    {
      cout << "Dialing bootstrap peer: " << bootstrap << "\n";
      status = abi.DialNode(node, bootstrap.c_str());
      if (status != CABI_STATUS_SUCCESS)
      {
        cerr << "Failed to dial bootstrap peer (" << bootstrap << "): "
             << statusMessage(status) << "\n";
      }
    }

    // Step 4. Dial to other client
    status = abi.DialNode(node, dialerAddr.c_str());
    if (status != CABI_STATUS_SUCCESS)
    {
      abi.FreeNode(node);
      throw std::runtime_error("cabi_node_dial failed: " + statusMessage(status));
    }


    // Step 5. Keeping node alive for duration
    std::this_thread::sleep_for(std::chrono::duration<float>(args.duration));

    // Step 6. Don't forget to free node
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
