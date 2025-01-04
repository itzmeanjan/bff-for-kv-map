#include "bench_common.hpp"
#include "binary_fuse_filter/filter_for_kv_map.hpp"
#include <benchmark/benchmark.h>
#include <cstdint>

static void
bench_construction_of_bff_for_kv_map(benchmark::State& state)
{
  constexpr size_t plaintext_modulo = 1024;
  constexpr size_t label = 256;

  const auto num_keys_in_kv_map = static_cast<size_t>(state.range(0));

  auto seed = generate_random_seed();

  std::vector<bff_kv_map_utils::bff_key_t> keys(num_keys_in_kv_map);
  std::vector<uint32_t> values(num_keys_in_kv_map, 0);

  generate_random_keys_and_values(keys, values, plaintext_modulo);

  for (auto _ : state) {
    benchmark::DoNotOptimize(seed);
    benchmark::DoNotOptimize(keys);
    benchmark::DoNotOptimize(values);

    try {
      bff_kv_map::bff_for_kv_map_t filter(seed, keys, values, plaintext_modulo, label);
      benchmark::ClobberMemory();
    } catch (std::runtime_error& err) {
    }
  }

  state.SetItemsProcessed(state.iterations());
}

BENCHMARK(bench_construction_of_bff_for_kv_map)
  ->Name("bff_for_kv_map/construct/10K")
  ->Arg(10'000)
  ->Unit(benchmark::TimeUnit::kMillisecond)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_construction_of_bff_for_kv_map)
  ->Name("bff_for_kv_map/construct/100K")
  ->Arg(100'000)
  ->Unit(benchmark::TimeUnit::kMillisecond)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_construction_of_bff_for_kv_map)
  ->Name("bff_for_kv_map/construct/1M")
  ->Arg(1'000'000)
  ->Unit(benchmark::TimeUnit::kSecond)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);

BENCHMARK(bench_construction_of_bff_for_kv_map)
  ->Name("bff_for_kv_map/construct/10M")
  ->Arg(10'000'000)
  ->Unit(benchmark::TimeUnit::kSecond)
  ->ComputeStatistics("min", compute_min)
  ->ComputeStatistics("max", compute_max);
