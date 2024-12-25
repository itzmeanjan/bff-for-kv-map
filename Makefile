CXX := clang++
CXX_FLAGS := -std=c++20
WARN_FLAGS := -Wall -Wextra -pedantic
OPT_FLAGS := -g -O2
I_FLAGS := -I ./include
SANITIZER_FLAGS := -fsanitize=address,leak,undefined -fno-omit-frame-pointer -fno-optimize-sibling-calls

SRC_DIR := include
BINARY_FUSE_FILTER_SOURCES := $(shell find include -name *.hpp)
BUILD_DIR := build

TEST_DIR := tests
TEST_SOURCES := $(wildcard $(TEST_DIR)/*.cpp)
TEST_BUILD_DIR := $(BUILD_DIR)/$(TEST_DIR)
TEST_OBJECTS := $(addprefix $(TEST_BUILD_DIR)/, $(notdir $(patsubst %.cpp,%.o,$(TEST_SOURCES))))
TEST_LINK_FLAGS := -lgtest -lgtest_main
TEST_BINARY := $(TEST_BUILD_DIR)/test.out

all: test

$(BUILD_DIR):
	mkdir -p $@

$(TEST_BUILD_DIR): $(BUILD_DIR)
	mkdir -p $@

$(TEST_BUILD_DIR)/%.o: $(TEST_DIR)/%.cpp $(TEST_BUILD_DIR)
	$(CXX) $(CXX_FLAGS) $(WARN_FLAGS) $(OPT_FLAGS) $(I_FLAGS) $(SANITIZER_FLAGS) -c $< -o $@

$(TEST_BINARY): $(TEST_OBJECTS)
	$(CXX) $(OPT_FLAGS) $(SANITIZER_FLAGS) $^ $(TEST_LINK_FLAGS) -o $@

test: $(TEST_BINARY)
	ASAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_summary=1' \
	UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1' \
	./$<

.PHONY: format clean

clean:
	rm -rf $(BUILD_DIR)

format: $(BINARY_FUSE_FILTER_SOURCES) $(TEST_SOURCES)
	clang-format -i $^
