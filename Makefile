.DEFAULT_GOAL := help

# Collects inspiration from https://github.com/itzmeanjan/ascon/blob/644e5c0ee64da42e3c187adb84ba4c43925caf30/Makefile
.PHONY: help
help:
	@for file in $(MAKEFILE_LIST); do \
		grep -E '^[a-zA-Z_-]+:.*?## .*$$' $${file} | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}';\
	done


CXX ?= clang++
CXX_DEFS +=
CXX_FLAGS := -std=c++20
WARN_FLAGS := -Wall -Wextra -Wpedantic
DEBUG_FLAGS := -O1 -g
RELEASE_FLAGS := -O3 -march=native
LINK_OPT_FLAGS := -flto

I_FLAGS := -I ./include

SRC_DIR := include
BFF_FOR_KV_MAP_SOURCES := $(shell find $(SRC_DIR) -name '*.hpp')
BUILD_DIR := build

include tests/test.mk
include benches/bench.mk
include examples/example.mk

.PHONY: clean
clean: ## Remove build directory
	rm -rf $(BUILD_DIR)

.PHONY: format
format: $(BFF_FOR_KV_MAP_SOURCES) $(TEST_SOURCES) $(TEST_HEADERS) $(BENCHMARK_SOURCES) $(BENCHMARK_HEADERS) $(EXAMPLE_SOURCES) $(EXAMPLE_HEADERS) ## Format source code
	clang-format -i $^
