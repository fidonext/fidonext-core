#pragma once

#include "abi_bindings.h"

namespace ping_example {

int runPingApp(const CabiRustLibp2p& abi, const Arguments& args);
bool loadAbi(const class DynamicLibrary& library, CabiRustLibp2p& abi);

} // namespace ping_example