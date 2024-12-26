#include "binary_fuse_filter/filter.hpp"
#include "binary_fuse_filter/utils.hpp"
#include <cstdint>
#include <gtest/gtest.h>
#include <random>

static void
generate_random_keys_and_values(std::span<bff_utils::bff_key_t> keys, std::span<uint32_t> values, const uint64_t plaintext_modulo)
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

TEST(BinaryFuseFilter, CreateFilterAndRecoverValuesWhenQueriedUsingKeys)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  binary_fuse_filter_Zp32_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  for (size_t i = 0; i < size; i++) {
    const uint32_t recovered = filter.recover(keys[i]);
    EXPECT_EQ(values[i], recovered);
  }
}

TEST(BinaryFuseFilter, SerializeAndDeserializeFilter)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  binary_fuse_filter_Zp32_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  std::vector<uint8_t> filter_as_bytes(filter.serialized_num_bytes());
  EXPECT_TRUE(filter.serialize(filter_as_bytes));

  binary_fuse_filter_Zp32_t filter_from_bytes(filter_as_bytes);

  for (size_t i = 0; i < size; i++) {
    const uint32_t recovered_filter1 = filter.recover(keys[i]);
    const uint32_t recovered_filter2 = filter_from_bytes.recover(keys[i]);

    EXPECT_EQ(recovered_filter1, recovered_filter2);
    EXPECT_EQ(values[i], recovered_filter1);
  }
}

TEST(BinaryFuseFilter, CheckBitsPerEntry)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  binary_fuse_filter_Zp32_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  const size_t bpe = filter.bits_per_entry();
  EXPECT_LT(bpe, std::log2(plaintext_modulo) + 2);
}
