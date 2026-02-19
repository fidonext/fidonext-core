#include "abi_bindings.h"

namespace ping_example {

// Converts ABI status codes to readable text for logs and errors in the example.
std::string statusMessage(const int status)
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

// Releases the currently owned ABI node and optionally stores a new one.
void NodeHandle::reset(void* newHandle)
{
  if (handle && abi && abi->FreeNode)
  {
    abi->FreeNode(handle);
  }

  handle = newHandle;
}

// RAII cleanup for node handle owned by this helper wrapper.
NodeHandle::~NodeHandle()
{
  reset();
}

} // namespace ping_example