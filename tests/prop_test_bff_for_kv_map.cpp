#include "binary_fuse_filter/filter_for_kv_map.hpp"
#include "binary_fuse_filter/utils.hpp"
#include "test_utils.hpp"
#include <gtest/gtest.h>

// Tests that a filter can be created, and that querying it with keys returns the correct values.
TEST(BinaryFuseFilter, CreateFilterAndRecoverValuesWhenQueriedUsingKeys)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_kv_map_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  bff_kv_map::bff_for_kv_map_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  for (size_t i = 0; i < size; i++) {
    const uint32_t recovered = filter.recover(keys[i]);
    EXPECT_EQ(values[i], recovered);
  }
}

// Tests that a filter can be serialized and deserialized, and that querying it with keys returns the correct values.
TEST(BinaryFuseFilter, SerializeAndDeserializeFilter)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_kv_map_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  bff_kv_map::bff_for_kv_map_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  std::vector<uint8_t> filter_as_bytes(filter.serialized_num_bytes());
  EXPECT_TRUE(filter.serialize(filter_as_bytes));

  bff_kv_map::bff_for_kv_map_t filter_from_bytes(filter_as_bytes);

  for (size_t i = 0; i < size; i++) {
    const uint32_t recovered_filter1 = filter.recover(keys[i]);
    const uint32_t recovered_filter2 = filter_from_bytes.recover(keys[i]);

    EXPECT_EQ(recovered_filter1, recovered_filter2);
    EXPECT_EQ(values[i], recovered_filter1);
  }
}

// Tests that the bits-per-entry is less than the theoretical maximum. The theoretical maximum is log2(plaintext_modulo) + 2.
// This test is inspired by https://github.com/claucece/chalamet/blob/515ff1479940a2917ad247acb6ab9e6d27e139a1/bff-modp/src/bfusep32.rs#L158-L173.
TEST(BinaryFuseFilter, CheckBitsPerEntry)
{
  constexpr size_t size = 100'000;
  constexpr uint64_t plaintext_modulo = 1024;
  constexpr uint64_t label = 1;

  std::vector<bff_kv_map_utils::bff_key_t> keys(size);
  std::vector<uint32_t> values(size, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  bff_kv_map::bff_for_kv_map_t filter(size);
  EXPECT_TRUE(filter.construct(keys, values, plaintext_modulo, label));

  const size_t bpe = filter.bits_per_entry();
  EXPECT_LT(bpe, std::log2(plaintext_modulo) + 2);
}
