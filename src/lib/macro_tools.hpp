#pragma once

#ifndef MACRO_TOOL_HPP
#define MACRO_TOOL_HPP

// NOLINTBEGIN(cppcoreguidelines-macro-usage, bugprone-macro-parentheses)

#define XSTR(s) STR(s)
#define STR(s) #s

#define EXPAND(x) x
#define STRINGIFY(x) #x
#define CONCAT(x, y) x##y
#define ASSIGN_OR_UNEXPECTED_NAME(x, y) CONCAT(x, y)

// Error handling macro
#define OSSL_CHECK_NULL_OR_UNEXPECTED(ptr, msg)                      \
  if ((ptr) == nullptr) {                                            \
    return std::unexpected(std::format("{} {}", __FUNCTION__, msg)); \
  }

#define OSSL_CHECK_OR_UNEXPECTED(good, msg)                          \
  if ((good) not_eq 1) {                                             \
    return std::unexpected(std::format("{} {}", __FUNCTION__, msg)); \
  }

#define UNEXPECTED_IF(condition, msg)                                     \
  if (condition) [[unlikely]] {                                           \
    return std::unexpected(std::format("({}): ({})", __FUNCTION__, msg)); \
  }

#define ASSIGN_OR_UNEXPECTED_IMPL(result_name, definition, expression) \
  auto &&result_name = (expression);                                   \
  if (not(result_name.has_value())) [[likely]] {                       \
    return std::unexpected(                                            \
        std::format("{}: {}", __FUNCTION__, result_name.error()));     \
  }                                                                    \
  definition = std::move(result_name.value());

#define ASSIGN_OR_UNEXPECTED(definition, expression)                        \
  ASSIGN_OR_UNEXPECTED_IMPL(                                                \
      ASSIGN_OR_UNEXPECTED_NAME(_error_or_value_, __COUNTER__), definition, \
      expression)

#define OSSL_ASSIGN_OR_UNEXPECTED_IMPL(result_name, definition, expression) \
  auto &&result_name = (expression);                                        \
  if (not(result_name.has_value())) {                                       \
    return std::unexpected(                                                 \
        std::format("{} {}", __FUNCTION__, result_name.error()));           \
  }                                                                         \
  definition = std::move(result_name.value());

#define OSSL_ASSIGN_OR_UNEXPECTED(definition, expression)                   \
  OSSL_ASSIGN_OR_UNEXPECTED_IMPL(                                           \
      ASSIGN_OR_UNEXPECTED_NAME(_error_or_value_, __COUNTER__), definition, \
      expression)

// NOLINTEND(cppcoreguidelines-macro-usage, bugprone-macro-parentheses)

#endif /* MACRO_TOOL_HPP */
