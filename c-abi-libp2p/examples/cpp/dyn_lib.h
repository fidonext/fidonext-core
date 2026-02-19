#pragma once

#include <string>

namespace ping_example {

class DynamicLibrary {
public:
  DynamicLibrary() = default;
  ~DynamicLibrary();

  DynamicLibrary(const DynamicLibrary&) = delete;
  DynamicLibrary& operator=(const DynamicLibrary&) = delete;

  bool load(const char* path);
  void* symbol(const char* name) const;
  void close();

private:
#ifdef _WIN32
  using LibHandle = void*;
#else
  using LibHandle = void*;
#endif

  LibHandle handle_ = nullptr;
};

const char* defaultLibraryName();

} // namespace ping_example