#pragma once
#include "binary_fuse_filter/utils.hpp"
#include <random>

// Generates random keys and values for testing purposes.
static inline void
generate_random_keys_and_values(std::span<bff_kv_map_utils::bff_key_t> keys, std::span<uint32_t> values, const uint64_t plaintext_modulo)
{
  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint32_t> dist_u32(0, plaintext_modulo - 1);
  std::uniform_int_distribution<uint64_t> dist_u64;

  for (size_t i = 0; i < keys.size(); i++) {
    keys[i].words[0] = dist_u64(gen);
    keys[i].words[1] = dist_u64(gen);
    keys[i].words[2] = dist_u64(gen);
    keys[i].words[3] = dist_u64(gen);

    values[i] = dist_u32(gen);
  }
}
