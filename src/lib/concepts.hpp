
#pragma once

#ifndef CONCEPTS_HPP
#define CONCEPTS_HPP

#include <concepts>  // for same_as
#include <ranges>    // for operator|, views, _Zip
#include <span>      // for span

namespace crypto {

template <class Type>
concept Integral = std::is_integral_v<Type>;

template <typename Type>
concept StringLike = std::is_convertible_v<Type, std::string>;

template <typename Type>
concept IsIterable = requires(Type value) {
  { std::begin(value) } -> std::input_iterator;
  { std::end(value) } -> std::input_iterator;
};  // NOLINT(readability/braces)
template <typename Type>
concept IsContainer = std::ranges::range<Type>;
template <typename Type>
concept IsStringContainer =
    IsContainer<Type> &&
    (std::same_as<std::ranges::range_value_t<Type>, std::string> or
     std::same_as<std::ranges::range_value_t<Type>, std::string_view>);

}  // namespace crypto

#endif /* CONCEPTS_HPP */
