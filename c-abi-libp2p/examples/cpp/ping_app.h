#pragma once

#include "abi_bindings.h"

namespace ping_example {

/// Executes the standalone ping workflow (node lifecycle, dials, and interactive IO loops).
int runPingApp(const CabiRustLibp2p& abi, const Arguments& args);

/// Resolves required C-ABI symbols from the loaded dynamic library into the ABI table.
bool loadAbi(const class DynamicLibrary& library, CabiRustLibp2p& abi);

} // namespace ping_example