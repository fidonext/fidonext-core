#pragma once

#include "abi_bindings.h"

namespace ping_example {

/// Parses CLI flags for the standalone ping example and returns normalized arguments.
Arguments parseArgs(int argc, char** argv);

} // namespace ping_example
