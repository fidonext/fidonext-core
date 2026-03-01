#include "dyn_lib.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace ping_example {

// Ensures loaded library is released when wrapper goes out of scope.
DynamicLibrary::~DynamicLibrary()
{
  close();
}

// Loads a shared library by path (cross-platform implementation).
bool DynamicLibrary::load(const char* path)
{
  close();
#ifdef _WIN32
  handle_ = reinterpret_cast<void*>(LoadLibraryA(path));
#else
  handle_ = dlopen(path, RTLD_LAZY);
#endif
  return handle_ != nullptr;
}

// Resolves a symbol from the currently loaded library.
void* DynamicLibrary::symbol(const char* name) const
{
  if (!handle_)
  {
    return nullptr;
  }
#ifdef _WIN32
  return reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(handle_), name));
#else
  return dlsym(handle_, name);
#endif
}

// Closes currently loaded library handle, if any.
void DynamicLibrary::close()
{
  if (!handle_)
  {
    return;
  }
#ifdef _WIN32
  FreeLibrary(reinterpret_cast<HMODULE>(handle_));
#else
  dlclose(handle_);
#endif
  handle_ = nullptr;
}

// Returns default ABI shared library filename for current platform.
const char* defaultLibraryName()
{
#ifdef _WIN32
  return "cabi_rust_libp2p.dll";
#else
  return "./libcabi_rust_libp2p.so";
#endif
}

} // namespace ping_example