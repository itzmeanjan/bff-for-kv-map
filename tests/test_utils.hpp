#pragma once
#include "binary_fuse_filter/utils.hpp"
#include <cstdint>
#include <random>

static inline std::array<uint8_t, 32>
generate_random_seed()
{
  std::array<uint8_t, 32> seed_bytes{};

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint8_t> dist_u8;

  for (auto& byte : seed_bytes) {
    byte = dist_u8(gen);
  }

  return seed_bytes;
}

// Generates random keys and values for testing purposes.
static inline void
generate_random_keys_and_values(std::span<bff_kv_map_utils::bff_key_t> keys, std::span<uint32_t> values, const uint64_t plaintext_modulo)
{
  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint32_t> dist_u32(0, plaintext_modulo - 1);
  std::uniform_int_distribution<uint64_t> dist_u64;

  for (auto& key : keys) {
    key.words[0] = dist_u64(gen);
    key.words[1] = dist_u64(gen);
    key.words[2] = dist_u64(gen);
    key.words[3] = dist_u64(gen);
  }

  for (auto& value : values) {
    value = dist_u32(gen);
  }
}
