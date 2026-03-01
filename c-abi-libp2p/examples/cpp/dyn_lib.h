#pragma once

#include <string>

namespace ping_example {

/// Small cross-platform RAII wrapper for runtime loading of the C-ABI shared library.
class DynamicLibrary {
public:
  /// Builds an empty wrapper without a loaded library.
  DynamicLibrary() = default;
  /// Closes an opened library handle on object destruction.
  ~DynamicLibrary();

  DynamicLibrary(const DynamicLibrary&) = delete;
  DynamicLibrary& operator=(const DynamicLibrary&) = delete;

  /// Loads a dynamic library by path and replaces any previously opened handle.
  bool load(const char* path);
  /// Returns a raw symbol pointer or nullptr when symbol/library is unavailable.
  void* symbol(const char* name) const;
  /// Closes currently loaded library handle; safe to call repeatedly.
  void close();

private:
#ifdef _WIN32
  using LibHandle = void*;
#else
  using LibHandle = void*;
#endif

  LibHandle handle_ = nullptr;
};

/// Returns default C-ABI library filename for the current target platform.
const char* defaultLibraryName();

} // namespace ping_example
