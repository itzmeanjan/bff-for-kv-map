# Binary Fuse Filter for Key-Value Maps
This project provides a C++ implementation of a Binary Fuse Filter (BFF) for key-value maps. This data structure allows for efficient storage and retrieval of values associated with keys, offering a balance between space efficiency and query speed. Unlike traditional hash tables, it enables value reconstruction during queries, eliminating the need to store values explicitly.

## Functionality
The BFF-for-KV-Map library offers:

* **Creation:** Constructs a BFF from a set of keys and their corresponding values. It employs a randomized construction algorithm to ensure a high probability of successful filter creation.
* **Serialization:** Serializes the filter into a byte array for storage or transmission.
* **Deserialization:** Reconstructs a BFF from its serialized byte representation.
* **Recovery:** Retrieves the value associated with a given key. The value is reconstructed from the filter's internal state, not directly retrieved from storage.
* **Metrics:** Provides methods to obtain the bits-per-entry and serialized size of the filter.

## Usage
### 1. Include Headers
Include the necessary header files in your C++ code:

```c++
#include "binary_fuse_filter/filter_for_kv_map.hpp"
#include "binary_fuse_filter/utils.hpp"
```

### 2. Data Structures
The library uses the following key structure:

```c++
struct bff_kv_map_utils::bff_key_t {
  std::array<uint64_t, 4> words{};
};
```

You need to represent your keys using this structure.

### 3. Construction
Construct a BFF from your key-value pairs:

```c++
#include <random>
#include <array>

// ... (Your key-value data) ...

std::array<uint8_t, 32> seed{};
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> distrib(0, 255);
for (int n = 0; n < 32; ++n) {
  seed[n] = distrib(gen);
}

std::vector<bff_kv_map_utils::bff_key_t> keys = { /* ... your keys ... */ };
std::vector<uint32_t> values = { /* ... your values ... */ };
uint64_t plaintext_modulo = 1024; // Choose an appropriate value. Must be >= 256.
uint64_t label = 12345; // Choose an arbitrary label.

bff_kv_map::bff_for_kv_map_t bff(seed, keys, values, plaintext_modulo, label);
```

### 4. Recovery
Retrieve a value using its key:

```c++
bff_kv_map_utils::bff_key_t query_key = { /* ... your query key ... */ };
uint32_t recovered_value = bff.recover(query_key);
```

### 5. Serialization and Deserialization
Serialize the BFF to a byte array:

```c++
const size_t serialized_size = bff.serialized_num_bytes();
std::vector<uint8_t> serialized_bff(serialized_size, 0);
bff.serialize(serialized_bff);
```

Deserialize the BFF from the byte array:

```c++
bff_kv_map::bff_for_kv_map_t deserialized_bff(serialized_bff);
```

## Build Instructions
This project uses a Makefile for building.  Make sure you have a C++20 compiler (like g++ or clang++),  Google Benchmark, and Google Test installed. On Debian/Ubuntu systems:

```bash
sudo apt-get install g++ libgoogle-benchmark-dev libgtest-dev
```

> ![NOTE]
> You can run `make` to show a help output for all available Make commands.

1. **Run Tests:** To run the tests, use the following commands:

```bash
make test -j                # Runs tests in release mode.
make debug_asan_test -j     # Runs tests in debug mode with AddressSanitizer (detects memory errors).  Requires AddressSanitizer to be properly configured in your compiler.
make release_asan_test -j   # Runs tests in release mode with AddressSanitizer.
make debug_ubsan_test -j    # Runs tests in debug mode with UndefinedBehaviorSanitizer (detects undefined behavior). Requires UndefinedBehaviorSanitizer to be properly configured in your compiler.
make release_ubsan_test -j  # Runs tests in release mode with UndefinedBehaviorSanitizer.
```

2. **Run Benchmarks:** To run the benchmarks, use these commands:

```bash
make benchmark  # Runs benchmarks without detailed CPU cycle counting.
make perf       # Runs benchmarks with CPU cycle counting (requires `libpfm4` to be installed: `sudo apt-get install libpfm4`).
```

## Dependencies
* C++20 compiler (g++, clang++)
* Google Benchmark, see [this](https://github.com/google/benchmark#installation)
* Google Test, see [this](https://github.com/google/googletest/tree/main/googletest#standalone-cmake-project)
* (Optional for `make perf`) `libpfm4`

## Notes
* The random seed is crucial for filter construction. Using a cryptographically secure random number generator is recommended for production environments.
* Error handling is included to catch issues like non-unique keys and invalid parameter values.

This README provides a basic overview. Refer to the source code for detailed implementation specifics and advanced usage options.
