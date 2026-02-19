#include "abi_bindings.h"
#include "cli_args.h"
#include "dyn_lib.h"
#include "ping_app.h"

#include <csignal>
#include <exception>
#include <iostream>

using namespace ping_example;

// Program entrypoint for the standalone C++ ping example.
// Pipeline is intentionally explicit because this file is part of public examples:
// 1) load shared C-ABI library,
// 2) resolve required symbols,
// 3) parse CLI arguments,
// 4) optionally enable Rust tracing in debug builds,
// 5) run the main ping scenario.
int main(int argc, char** argv)
{
  // Step 1. Load the dynamic C-ABI library.
  DynamicLibrary library;
  if (!library.load(defaultLibraryName()))
  {
    std::cerr << "Error loading lib: " << defaultLibraryName() << "\n";
    return 1;
  }

  // Step 2. Resolve required exported C-ABI functions.
  CabiRustLibp2p abi{};
  if (!loadAbi(library, abi))
  {
    std::cerr << "Missing required functions in library\n";
    return 1;
  }

  // Step 3. Parse example CLI arguments.
  Arguments args;
  try
  {
    args = parseArgs(argc, argv);
  }
  catch (const std::exception& ex)
  {
    std::cerr << "Argument error: " << ex.what() << "\n";
    return 1;
  }

#if _DEBUG
  // Step 4. Enable Rust tracing in debug sessions.
  if (abi.InitTracing() != CABI_STATUS_SUCCESS)
  {
    std::cerr << "Failed to initialize tracing. Continuing without tracing\n";
  }
#endif

  // Handle Ctrl+C so interactive loops can stop gracefully.
  auto signalHandler = [](int) {};
  std::signal(SIGINT, signalHandler);

  try
  {
    // Step 5. Run the example workflow (node creation, dialing, send/recv loops).
    return runPingApp(abi, args);
  }
  catch (const std::exception& ex)
  {
    std::cerr << "Fatal error: " << ex.what() << "\n";
    return 1;
  }
}
