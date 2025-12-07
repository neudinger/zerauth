#include "tools.hpp"

#include <algorithm>    // for generate_n
#include <iterator>     // for back_insert_iterator, back_inserter
#include <random>       // for random_device, uniform_int_distribution
#include <string_view>  // for string_view

namespace crypto {
[[nodiscard]]
auto generate_random_string(std::size_t const length) noexcept -> std::string {
  std::string_view constexpr char_pool =
      " "
      "!\"#$%&'()*+,-./"
      "0123456789"
      ":;<=>?@"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "[\\]^_`"
      "abcdefghijklmnopqrstuvwxyz"
      "{|}~";

  auto constexpr pool_size = char_pool.length();

  std::random_device random_device;
  std::uniform_int_distribution<std::size_t> distribution(0, pool_size - 1);
  std::string random_string;
  random_string.reserve(length);

  auto generator = [&]() -> char {
    return char_pool[distribution(random_device)];
  };

  std::generate_n(std::back_inserter(random_string), length, generator);
  return random_string;
}
}  // namespace crypto
