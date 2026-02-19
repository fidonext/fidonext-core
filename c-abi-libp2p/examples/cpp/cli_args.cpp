#include "cli_args.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace ping_example {

namespace {

// Returns default listen address for the selected transport.
std::string defaultListen(const bool useQuic)
{
  return useQuic ? "/ip4/127.0.0.1/udp/41000/quic-v1" : "/ip4/127.0.0.1/tcp/41000";
}

// Parses a 64-char hex string into a 32-byte deterministic identity seed.
std::array<uint8_t, 32> parseSeed(const std::string& hexSeed)
{
  if (hexSeed.size() != 64)
  {
    throw std::invalid_argument("seed must contain exactly 64 hex characters (32 bytes)");
  }

  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < seed.size(); ++i)
  {
    const auto byteStr = hexSeed.substr(i * 2, 2);
    char* endPtr = nullptr;
    const auto value = std::strtoul(byteStr.c_str(), &endPtr, 16);
    if (endPtr == byteStr.c_str() || value > 0xFF)
    {
      throw std::invalid_argument("seed contains non-hex characters");
    }
    seed[i] = static_cast<uint8_t>(value);
  }
  return seed;
}

// Derives a deterministic 32-byte seed from an arbitrary phrase.
std::array<uint8_t, 32> deriveSeedFromString(const std::string& seedPhrase)
{
  constexpr uint64_t FNV_OFFSET = 0xcbf29ce484222325ULL;
  constexpr uint64_t FNV_PRIME = 0x100000001b3ULL;

  std::array<uint64_t, 4> lanes{
    FNV_OFFSET ^ 0x736565646c616e65ULL,
    FNV_OFFSET ^ 0x706872617365313ULL,
    FNV_OFFSET ^ 0x706872617365323ULL,
    FNV_OFFSET ^ 0x706872617365333ULL,
  };

  for (const unsigned char byte : seedPhrase)
  {
    for (size_t i = 0; i < lanes.size(); ++i)
    {
      lanes[i] ^= static_cast<uint64_t>(byte) + (0x9e3779b97f4a7c15ULL * i);
      lanes[i] *= (FNV_PRIME + (i * 2));
      lanes[i] ^= lanes[(i + 1) % lanes.size()] >> (8 * (i + 1));
    }
  }

  std::array<uint8_t, 32> seed{};
  for (size_t i = 0; i < lanes.size(); ++i)
  {
    const uint64_t value = lanes[i];
    seed[i * 8 + 0] = static_cast<uint8_t>((value >> 0) & 0xFF);
    seed[i * 8 + 1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    seed[i * 8 + 2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    seed[i * 8 + 3] = static_cast<uint8_t>((value >> 24) & 0xFF);
    seed[i * 8 + 4] = static_cast<uint8_t>((value >> 32) & 0xFF);
    seed[i * 8 + 5] = static_cast<uint8_t>((value >> 40) & 0xFF);
    seed[i * 8 + 6] = static_cast<uint8_t>((value >> 48) & 0xFF);
    seed[i * 8 + 7] = static_cast<uint8_t>((value >> 56) & 0xFF);
  }

  return seed;
}

// Prints help and exits; this is a demo CLI so usage is intentionally explicit.
void printUsageAndExit()
{
  std::cout << "relay_chat usage:\n"
            << "  --role relay|leaf (default: leaf)\n"
            << "  --use-quic\n"
            << "  --listen <multiaddr>\n"
            << "  --bootstrap <multiaddr> (repeatable)\n"
            << "  --force-hop (relay only; start with hop enabled without waiting for AutoNAT)\n"
            << "  --target <multiaddr> (repeatable)\n"
            << "  --seed <64-hex-bytes> (deterministic PeerId)\n"
            << "  --seed-phrase <string> (derive 32-byte seed deterministically)\n";
  std::exit(0);
}

} // namespace

// Parses the CLI and returns normalized arguments for runPingApp().
Arguments parseArgs(const int argc, char** argv)
{
  Arguments args;
  bool listenProvided = false;
  bool seedProvided = false;

  for (int i = 1; i < argc; ++i)
  {
    const std::string arg = argv[i];

    if (arg == "--role" && i + 1 < argc)
    {
      const std::string roleValue = argv[++i];
      if (roleValue == "relay")
      {
        args.role = Role::Relay;
      }
      else if (roleValue == "leaf")
      {
        args.role = Role::Leaf;
      }
      else
      {
        throw std::invalid_argument("--role must be 'relay' or 'leaf'");
      }
    }
    else if (arg == "--use-quic")
    {
      args.useQuic = true;
    }
    else if (arg == "--force-hop")
    {
      args.forceHop = true;
    }
    else if (arg == "--listen" && i + 1 < argc)
    {
      args.listen = argv[++i];
      listenProvided = true;
    }
    else if (arg == "--bootstrap" && i + 1 < argc)
    {
      args.bootstrapPeers.emplace_back(argv[++i]);
    }
    else if (arg == "--target" && i + 1 < argc)
    {
      args.targetPeers.emplace_back(argv[++i]);
    }
    else if (arg == "--seed" && i + 1 < argc)
    {
      if (seedProvided)
      {
        throw std::invalid_argument("--seed/--seed-phrase are mutually exclusive");
      }
      args.identitySeed = parseSeed(argv[++i]);
      seedProvided = true;
    }
    else if (arg == "--seed-phrase" && i + 1 < argc)
    {
      if (seedProvided)
      {
        throw std::invalid_argument("--seed/--seed-phrase are mutually exclusive");
      }
      args.identitySeed = deriveSeedFromString(argv[++i]);
      seedProvided = true;
    }
    else if (arg == "--help" || arg == "-h")
    {
      printUsageAndExit();
    }
    else
    {
      throw std::invalid_argument("Unknown argument: " + arg);
    }
  }

  if (!listenProvided)
  {
    args.listen = defaultListen(args.useQuic);
  }

  return args;
}

} // namespace ping_example