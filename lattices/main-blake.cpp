// --- Verification ---

#include <print>

#include "blake3.hpp"

constexpr size_t hash_test_size = 32UL;

constexpr std::array<uint8_t, hash_test_size> k_expected_hello = {
    0xea, 0x8f, 0x16, 0x3d, 0xb3, 0x86, 0x82, 0x92, 0x5e, 0x44, 0x91,
    0xc5, 0xe5, 0x8d, 0x4b, 0xb3, 0x50, 0x6e, 0xf8, 0xc1, 0x4e, 0xb7,
    0x8a, 0x86, 0xe9, 0x08, 0xc5, 0x62, 0x4a, 0x67, 0x20, 0x0f};

constexpr std::array<uint8_t, hash_test_size> k_expected_empty = {
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d,
    0xea, 0x36, 0xdc, 0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1,
    0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62};

template <size_t HashSize = blake3::hash_default_size>
consteval auto check_hash(std::string_view input_str,
                          std::array<uint8_t, HashSize> const& expected_bytes)
    -> bool {
  auto result_bytes = blake3::hash(input_str);
  for (size_t index{}; index < HashSize; ++index) {
    if (result_bytes.at(index) != expected_bytes.at(index)) {
      return false;
    }
  }
  return true;
}

static_assert(check_hash("hello", k_expected_hello),
              "Hash of 'hello' failed CTFE check");
static_assert(check_hash("", k_expected_empty),
              "Hash of empty string failed CTFE check");

using namespace std::literals;

// clang++ -O3 --std=c++23 main-blake.cpp  && ./a.out
auto main() -> int {
  auto constexpr hash_val = blake3::hash("hello"sv);

  std::print("Input: \"hello\"\n");
  std::println("BLAKE3 Hash: size = {} ", hash_val.size());

  for (uint8_t const byte_val : hash_val) {
    std::print("0x{:02x}, ", byte_val);
  }
  std::println();

  if (hash_val == k_expected_hello) {
    std::println("Status: Verified ✅");
  } else {
    std::println("Status: Failed ❌");
  }

  return 0;
}