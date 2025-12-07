#pragma once

#include <cstddef>
#include <string>

#ifndef TOOLS_HPP
#define TOOLS_HPP

namespace crypto {

[[nodiscard]]
auto generate_random_string(std::size_t length) noexcept -> std::string;
}
#endif /* TOOLS_HPP */