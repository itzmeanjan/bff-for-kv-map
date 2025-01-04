#include "bench_common.hpp"
#include "binary_fuse_filter/filter_for_kv_map.hpp"
#include <benchmark/benchmark.h>
#include <cstdint>

static void
bench_recover_from_bff_for_kv_map(benchmark::State& state)
{
  constexpr size_t plaintext_modulo = 1024;
  constexpr size_t label = 256;

  const auto num_keys_in_kv_map = static_cast<size_t>(state.range(0));

  std::vector<bff_kv_map_utils::bff_key_t> keys(num_keys_in_kv_map);
  std::vector<uint32_t> values(num_keys_in_kv_map, 0);

  auto seed = generate_random_seed();
  generate_random_keys_and_values(keys, values, plaintext_modulo);

  bff_kv_map::bff_for_kv_map_t filter;

  bool is_constructed = false;
  while (!is_constructed) {
    try {
      filter = bff_kv_map::bff_for_kv_map_t(seed, keys, values, plaintext_modulo, label);
      is_constructed = true;
    } catch (std::runtime_error& err) {
      seed = generate_random_seed();
    }
  }

  size_t key_idx = 0;
  uint32_t value = 0;

  for (auto _ : state) {
    benchmark::DoNotOptimize(filter);
    benchmark::DoNotOptimize(keys);
    benchmark::DoNotOptimize(key_idx);
    benchmark::DoNotOptimize(value);

    value ^= filter.recover(keys[key_idx]);

    benchmark::ClobberMemory();

    key_idx++;
    key_idx %= keys.size();
  }

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(bench_recover_from_bff_for_kv_map)
  ->Arg(10'000)
  ->Name("bff_for_kv_map/recover/10K Keys")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_recover_from_bff_for_kv_map)
  ->Arg(100'000)
  ->Name("bff_for_kv_map/recover/100K Keys")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_recover_from_bff_for_kv_map)
  ->Arg(1'000'000)
  ->Name("bff_for_kv_map/recover/1M Keys")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_recover_from_bff_for_kv_map)
  ->Arg(10'000'000)
  ->Name("bff_for_kv_map/recover/10M Keys")
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
