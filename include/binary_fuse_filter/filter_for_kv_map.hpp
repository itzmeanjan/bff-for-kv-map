#pragma once
#include "utils.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <span>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace bff_kv_map {

constexpr size_t BFF_FOR_KV_MAP_MAX_CREATE_ATTEMPT_COUNT = 100;

struct bff_for_kv_map_t
{
private:
  std::array<uint8_t, 32> seed{};

  uint32_t num_keys_in_kv_map;
  uint64_t plaintext_modulo;
  uint64_t label;

  uint32_t segment_length;
  uint32_t segment_length_mask;
  uint32_t segment_count;
  uint32_t segment_count_length;
  uint32_t array_length;
  std::vector<uint32_t> fingerprints;

public:
  bff_for_kv_map_t(const uint32_t num_keys)
  {
    constexpr uint32_t arity = 3;
    segment_length = num_keys == 0 ? 4 : bff_kv_map_utils::calculate_segment_length(arity, num_keys);
    if (segment_length > 262144) {
      segment_length = 262144;
    }

    this->num_keys_in_kv_map = num_keys;
    segment_length_mask = segment_length - 1;

    const double sizeFactor = num_keys <= 1 ? 0 : bff_kv_map_utils::calculate_size_factor(arity, num_keys);
    const uint32_t capacity = num_keys <= 1 ? 0 : static_cast<uint32_t>(round(static_cast<double>(num_keys) * sizeFactor));
    const uint32_t initSegmentCount = (capacity + segment_length - 1) / segment_length - (arity - 1);

    array_length = (initSegmentCount + arity - 1) * segment_length;
    segment_count = (array_length + segment_length - 1) / segment_length;

    if (segment_count <= arity - 1) {
      segment_count = 1;
    } else {
      segment_count = segment_count - (arity - 1);
    }

    array_length = (segment_count + arity - 1) * segment_length;
    segment_count_length = segment_count * segment_length;

    fingerprints = std::vector<uint32_t>(array_length, 0);
  }

  bff_for_kv_map_t(std::span<const uint8_t> bytes)
  {
    size_t buffer_offset = 0;

    std::copy_n(bytes.subspan(buffer_offset).begin(), seed.size(), seed.begin());
    buffer_offset += seed.size();

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(num_keys_in_kv_map), reinterpret_cast<uint8_t*>(&num_keys_in_kv_map));
    buffer_offset += sizeof(num_keys_in_kv_map);

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(plaintext_modulo), reinterpret_cast<uint8_t*>(&plaintext_modulo));
    buffer_offset += sizeof(plaintext_modulo);

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(label), reinterpret_cast<uint8_t*>(&label));
    buffer_offset += sizeof(label);

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(segment_length), reinterpret_cast<uint8_t*>(&segment_length));
    buffer_offset += sizeof(segment_length);

    segment_length_mask = segment_length - 1;

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(segment_count), reinterpret_cast<uint8_t*>(&segment_count));
    buffer_offset += sizeof(segment_count);

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(segment_count_length), reinterpret_cast<uint8_t*>(&segment_count_length));
    buffer_offset += sizeof(segment_count_length);

    std::copy_n(bytes.subspan(buffer_offset).begin(), sizeof(array_length), reinterpret_cast<uint8_t*>(&array_length));
    buffer_offset += sizeof(array_length);

    fingerprints = std::vector<uint32_t>(array_length, 0);
    std::copy_n(bytes.subspan(buffer_offset).begin(), array_length * sizeof(uint32_t), reinterpret_cast<uint8_t*>(fingerprints.data()));
  }

  ~bff_for_kv_map_t()
  {
    seed.fill(0);

    num_keys_in_kv_map = 0;
    plaintext_modulo = 0;
    label = 0;

    segment_length = 0;
    segment_length_mask = 0;
    segment_count = 0;
    segment_count_length = 0;
    array_length = 0;
    fingerprints.clear();
  }

  size_t bits_per_entry() const { return (fingerprints.size() * static_cast<size_t>(std::log2(plaintext_modulo))) / static_cast<size_t>(num_keys_in_kv_map); }

  size_t serialized_num_bytes()
  {
    return sizeof(seed) + sizeof(num_keys_in_kv_map) + sizeof(plaintext_modulo) + sizeof(label) + sizeof(segment_length) + sizeof(segment_count) +
           sizeof(segment_count_length) + sizeof(array_length) + (fingerprints.size() * sizeof(uint32_t));
  }

  bool serialize(std::span<uint8_t> bytes)
  {
    if (bytes.size() != serialized_num_bytes()) [[unlikely]] {
      return false;
    }

    size_t buffer_offset = 0;
    std::copy_n(seed.begin(), seed.size(), bytes.begin());

    buffer_offset += seed.size();
    std::copy_n(reinterpret_cast<const uint8_t*>(&num_keys_in_kv_map), sizeof(num_keys_in_kv_map), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(num_keys_in_kv_map);
    std::copy_n(reinterpret_cast<const uint8_t*>(&plaintext_modulo), sizeof(plaintext_modulo), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(plaintext_modulo);
    std::copy_n(reinterpret_cast<const uint8_t*>(&label), sizeof(label), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(label);
    std::copy_n(reinterpret_cast<const uint8_t*>(&segment_length), sizeof(segment_length), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(segment_length);
    std::copy_n(reinterpret_cast<const uint8_t*>(&segment_count), sizeof(segment_count), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(segment_count);
    std::copy_n(reinterpret_cast<const uint8_t*>(&segment_count_length), sizeof(segment_count_length), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(segment_count_length);
    std::copy_n(reinterpret_cast<const uint8_t*>(&array_length), sizeof(array_length), bytes.subspan(buffer_offset).begin());

    buffer_offset += sizeof(array_length);
    std::copy_n(reinterpret_cast<const uint8_t*>(fingerprints.data()), array_length * sizeof(uint32_t), bytes.subspan(buffer_offset).begin());

    return true;
  }

  bool construct(std::span<const bff_kv_map_utils::bff_key_t> keys, // 256 -bit keys
                 std::span<const uint32_t> values,                  // Corresponding values s.t. ∈ [0,plaintext_modulo)
                 const uint64_t plaintext_modulo,
                 const uint64_t label)
  {
    if (num_keys_in_kv_map != keys.size()) [[unlikely]] {
      return false;
    }
    if (keys.size() != values.size()) [[unlikely]] {
      return false;
    }
    if (!bff_kv_map_utils::are_all_keys_distinct(keys)) [[unlikely]] {
      return false;
    }
    if (plaintext_modulo < 256) [[unlikely]] {
      return false;
    }

    this->plaintext_modulo = plaintext_modulo;
    this->label = label;

    const uint32_t capacity = array_length;

    std::vector<uint64_t> reverseOrder(num_keys_in_kv_map + 1, 0);
    std::vector<uint32_t> alone(capacity, 0);
    std::vector<uint8_t> t2count(capacity, 0);
    std::vector<uint8_t> reverseH(num_keys_in_kv_map, 0);
    std::vector<uint64_t> t2hash(capacity, 0);

    uint32_t block_bits = 1;
    while ((1U << block_bits) < segment_count) {
      block_bits += 1;
    }

    const uint32_t block_size = 1U << block_bits;
    std::vector<uint32_t> startPos(block_size, 0);

    std::array<uint32_t, 5> h012{};
    reverseOrder[num_keys_in_kv_map] = 1;

    std::unordered_map<uint64_t, uint32_t> hm_keys{};

    for (size_t loop = 0; true; loop++) {
      if ((loop + 1) > BFF_FOR_KV_MAP_MAX_CREATE_ATTEMPT_COUNT) [[unlikely]] {
        return false;
      }

      for (uint32_t i = 0; i < block_size; i++) {
        startPos[i] = static_cast<uint32_t>((static_cast<uint64_t>(i) * keys.size()) >> block_bits);
      }

      uint64_t maskblock = block_size - 1;
      for (uint32_t i = 0; i < num_keys_in_kv_map; i++) {
        const uint64_t hash = bff_kv_map_utils::mix256(keys[i].words, seed);

        uint64_t segment_index = hash >> (64 - block_bits);
        while (reverseOrder[startPos[segment_index]] != 0) {
          segment_index++;
          segment_index &= maskblock;
        }

        reverseOrder[startPos[segment_index]] = hash;
        startPos[segment_index]++;

        hm_keys[hash] = values[i];
      }

      bool error = 0;
      for (uint32_t i = 0; i < num_keys_in_kv_map; i++) {
        const uint64_t hash = reverseOrder[i];
        const auto [h0, h1, h2] = hash_batch(hash);

        t2count[h0] += 4;
        t2hash[h0] ^= hash;

        t2count[h1] += 4;
        t2count[h1] ^= 1U;
        t2hash[h1] ^= hash;

        t2count[h2] += 4;
        t2hash[h2] ^= hash;
        t2count[h2] ^= 2U;

        error = (t2count[h0] < 4) || (t2count[h1] < 4) || (t2count[h2] < 4);
      }

      if (error) {
        std::fill(reverseOrder.begin(), reverseOrder.end(), 0);
        std::fill(t2count.begin(), t2count.end(), 0);
        std::fill(t2hash.begin(), t2hash.end(), 0);

        continue;
      }

      uint32_t Qsize = 0;
      for (uint32_t i = 0; i < capacity; i++) {
        alone[Qsize] = i;
        Qsize += ((t2count[i] >> 2U) == 1) ? 1U : 0U;
      }

      uint32_t stacksize = 0;
      while (Qsize > 0) {
        Qsize--;
        const uint32_t index = alone[Qsize];

        if ((t2count[index] >> 2U) == 1) {
          const uint64_t hash = t2hash[index];

          const uint8_t found = t2count[index] & 3U;
          reverseH[stacksize] = found;
          reverseOrder[stacksize] = hash;
          stacksize++;

          const auto [h0, h1, h2] = hash_batch(hash);

          h012[1] = h1;
          h012[2] = h2;
          h012[3] = h0;
          h012[4] = h012[1];

          const uint32_t other_index1 = h012[found + 1];
          alone[Qsize] = other_index1;
          Qsize += ((t2count[other_index1] >> 2U) == 2 ? 1U : 0U);

          t2count[other_index1] -= 4;
          t2count[other_index1] ^= bff_kv_map_utils::mod3(found + 1);
          t2hash[other_index1] ^= hash;

          const uint32_t other_index2 = h012[found + 2];
          alone[Qsize] = other_index2;
          Qsize += ((t2count[other_index2] >> 2U) == 2 ? 1U : 0U);

          t2count[other_index2] -= 4;
          t2count[other_index2] ^= bff_kv_map_utils::mod3(found + 2);
          t2hash[other_index2] ^= hash;
        }
      }

      if (stacksize == num_keys_in_kv_map) {
        break;
      }

      std::fill(reverseOrder.begin(), reverseOrder.end(), 0);
      std::fill(t2count.begin(), t2count.end(), 0);
      std::fill(t2hash.begin(), t2hash.end(), 0);
    }

    for (uint32_t i = num_keys_in_kv_map - 1; i < num_keys_in_kv_map; i--) {
      const uint64_t hash = reverseOrder[i];
      const uint32_t value = hm_keys[hash];

      const auto [h0, h1, h2] = hash_batch(hash);

      const uint8_t found = reverseH[i];
      h012[0] = h0;
      h012[1] = h1;
      h012[2] = h2;
      h012[3] = h012[0];
      h012[4] = h012[1];

      const uint32_t entry = ((value % plaintext_modulo) - fingerprints[h012[found + 1]] - fingerprints[h012[found + 2]]) % plaintext_modulo;
      const uint32_t mask = bff_kv_map_utils::mix(hash, label) % plaintext_modulo;

      fingerprints[h012[found]] = (entry - mask) % plaintext_modulo;
    }

    return true;
  }

  uint32_t recover(const bff_kv_map_utils::bff_key_t key)
  {
    const uint64_t hash = bff_kv_map_utils::mix256(key.words, seed);
    const auto [h0, h1, h2] = hash_batch(hash);

    const uint32_t data = fingerprints[h0] + fingerprints[h1] + fingerprints[h2];
    const uint32_t mask = bff_kv_map_utils::mix(hash, label) % plaintext_modulo;

    return (data + mask) % plaintext_modulo;
  }

  std::vector<uint32_t> get_fingerprints_mod_p() const
  {
    std::vector<uint32_t> result;
    result.reserve(fingerprints.size());

    for (const auto f : fingerprints) {
      result.push_back(f % static_cast<uint32_t>(plaintext_modulo));
    }

    return result;
  }

  std::array<uint32_t, 3> get_hash_evals(const bff_kv_map_utils::bff_key_t key) const
  {
    const auto hash = bff_kv_map_utils::mix256(key.words, seed);
    const auto [h0, h1, h2] = hash_batch(hash);

    return { h0, h1, h2 };
  }

  uint64_t get_key_fingerprint(const bff_kv_map_utils::bff_key_t key) const
  {
    const auto hash = bff_kv_map_utils::mix256(key.words, seed);
    return bff_kv_map_utils::mix(hash, label);
  }

private:
  constexpr uint32_t hash(uint64_t index, uint64_t hash) const
  {
    uint64_t h = bff_kv_map_utils::mulhi(hash, this->segment_count_length);
    h += index * this->segment_length;

    // keep the lower 36 bits
    const uint64_t hh = hash & ((1ULL << 36U) - 1);

    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & this->segment_length_mask);

    return (uint32_t)h;
  }

  constexpr std::tuple<uint32_t, uint32_t, uint32_t> hash_batch(const uint64_t hash) const
  {
    const uint64_t hi = bff_kv_map_utils::mulhi(hash, this->segment_count_length);

    uint32_t h0 = 0, h1 = 0, h2 = 0;

    h0 = (uint32_t)hi;
    h1 = h0 + this->segment_length;
    h2 = h1 + this->segment_length;
    h1 ^= (uint32_t)(hash >> 18U) & this->segment_length_mask;
    h2 ^= (uint32_t)(hash) & this->segment_length_mask;

    return { h0, h1, h2 };
  }
};

}
