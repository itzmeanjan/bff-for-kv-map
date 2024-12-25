#pragma once
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <set>
#include <span>

namespace bff_utils {

struct bff_key_t
{
public:
  std::array<uint64_t, 4> words{};

  bff_key_t() = default;
  auto operator<=>(const auto& rhs) const
  {
    return std::lexicographical_compare_three_way(this->words.begin(), this->words.end(), rhs.words.begin(), rhs.words.end());
  }
};

static inline bool
are_all_keys_distinct(std::span<const bff_key_t> keys)
{
  std::set<bff_key_t> s;

  for (auto key : keys) {
    auto [_, has_inserted] = s.insert(key);
    if (!has_inserted) {
      return false;
    }
  }

  return true;
}

static constexpr uint32_t
fingerprint(const uint64_t hash)
{
  return (uint32_t)(hash ^ (hash >> 32U));
}

static constexpr uint32_t
calculate_segment_length(const uint32_t arity, const uint32_t size)
{
  // These parameters are very sensitive. Replacing 'floor' by 'round' can substantially affect the construction time.
  if (arity == 3) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(3.33) + 2.25));
  }
  if (arity == 4) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(2.91) - 0.5));
  }
  return 65536;
}

static constexpr double
calculate_size_factor(const uint32_t arity, const uint32_t size)
{
  if (arity == 3) {
    return std::max(1.125, 0.875 + 0.25 * log(1000000.0) / log((double)size));
  }
  if (arity == 4) {
    return std::max(1.075, 0.77 + 0.305 * log(600000.0) / log((double)size));
  }
  return 2.0;
}

static constexpr uint8_t
mod3(const uint8_t x)
{
  return (x > 2) ? (x - 3) : x;
}

static constexpr uint64_t
murmur64(uint64_t h)
{
  h ^= h >> 33U;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33U;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33U;

  return h;
}

static constexpr uint64_t
mix(const uint64_t key, const uint64_t seed)
{
  return murmur64(key + seed);
}

static inline uint64_t
mix256(std::span<const uint64_t, 4> key, std::span<const uint8_t, 32> seed)
{
  std::array<uint64_t, key.size()> seed_words{};
  memcpy(seed_words.data(), seed.data(), seed.size_bytes());

  uint64_t mixed_outer = 0;
  for (size_t key_idx = 0; key_idx < 4; key_idx++) {
    uint64_t mixed_inner = 0;

    for (size_t seed_idx = 0; seed_idx < 4; seed_idx++) {
      mixed_inner = murmur64(mixed_inner + mix(key[key_idx], seed_words[seed_idx]));
    }

    mixed_outer += mixed_inner;
  }
  return mixed_outer;
}

static constexpr uint64_t
mulhi(uint64_t a, uint64_t b)
{
#ifdef __SIZEOF_INT128__

  return (uint64_t)(((__uint128_t)a * b) >> 64U);

#elif defined(_M_X64) || defined(_MARM64)

  return __umulh(a, b);

#elif defined(_M_IA64)

  unsigned __int64 hi;
  (void)_umul128(a, b, &hi);
  return hi;

#else

  const uint64_t a0 = (uint32_t)a;
  const uint64_t a1 = a >> 32;
  const uint64_t b0 = (uint32_t)b;
  const uint64_t b1 = b >> 32;
  const uint64_t p11 = a1 * b1;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p00 = a0 * b0;

  const uint64_t middle = p10 + (p00 >> 32) + (uint32_t)p01;
  return p11 + (middle >> 32) + (p01 >> 32);

#endif
}

}
