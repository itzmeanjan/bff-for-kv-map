#include "binary_fuse_filter/filter_for_kv_map.hpp"
#include "binary_fuse_filter/utils.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <random>
#include <vector>

std::pair<std::vector<bff_kv_map_utils::bff_key_t>, std::vector<uint32_t>>
generate_random_keys_and_values(const size_t num_keys, const uint64_t plaintext_modulo)
{
  std::vector<bff_kv_map_utils::bff_key_t> keys(num_keys);
  std::vector<uint32_t> values(num_keys);

  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint8_t> dist_u8;
  std::uniform_int_distribution<uint32_t> dist_u32(0, plaintext_modulo - 1);

  auto rand_gen = [&]() { return dist_u8(gen); };

  for (auto& key : keys) {
    std::array<uint8_t, 32> key_bytes;
    std::ranges::generate(key_bytes, rand_gen);

    key = bff_kv_map_utils::bff_key_t(key_bytes);
  }

  for (auto& value : values) {
    value = dist_u32(gen);
  }

  return { keys, values };
}

int
main()
{
  constexpr size_t num_keys = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 12345;

  auto [keys, values] = generate_random_keys_and_values(num_keys, plaintext_modulo);

  std::array<uint8_t, 32> seed{};
  std::fill(seed.begin(), seed.end(), 0xCA);

  bff_kv_map::bff_for_kv_map_t bff;

  try {
    bff = bff_kv_map::bff_for_kv_map_t(seed, keys, values, plaintext_modulo, label);

    std::cout << "Number of keys: " << num_keys << "\n";
    std::cout << "Plaintext modulo: " << plaintext_modulo << "\n";
    std::cout << "Bits per entry: " << bff.bits_per_entry() << "\n";
    std::cout << "Serialized size: " << bff.serialized_num_bytes() << " bytes" << "\n";

    std::vector<uint8_t> serialized_bff(bff.serialized_num_bytes());
    bff.serialize(serialized_bff);

    bff_kv_map::bff_for_kv_map_t deserialized_bff(serialized_bff);

    bool failed_to_recover = false;
    for (size_t i = 0; i < num_keys; ++i) {
      const uint32_t recovered_value = deserialized_bff.recover(keys[i]);
      if (recovered_value != values[i]) {
        std::cout << "Recovery failed for key " << i << ": (recovered value: " << recovered_value << ") (original: " << values[i] << ")" << "\n";
        failed_to_recover = true;
      }
    }

    if (!failed_to_recover) {
      std::cout << "All values recovered correctly !\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "Error during BFF construction: " << e.what() << "\n";
    return 0; // Yes, we are suppressing the error.
  }

  return 0;
}
