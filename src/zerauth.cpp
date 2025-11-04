#include <sys/types.h>

#include <expected>
#include <format>
#include <ranges>

#include <flatbuffers/buffer.h>
#include <flatbuffers/flatbuffer_builder.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/idl.h>
#include <flatbuffers/reflection.h>
#include <flatbuffers/util.h>
#include <flatbuffers/verifier.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>

#include <print>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iterator>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include <array>
#include <flatbuffer/proving_phase_generated.h>
#include <flatbuffer/setup_phase_generated.h>
#include <flatbuffer/transient_generated.h>
#include <span>
#include <type_traits>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
// #include <GLES3/gl3.h>
#include <emscripten/bind.h>
#else
#endif

namespace crypto {
#define XSTR(s) STR(s)
#define STR(s) #s

#define EXPAND(x) x
#define STRINGIFY(x) #x
#define CONCAT(x, y) x##y
#define ASSIGN_OR_UNEXPECTED_NAME(x, y) CONCAT(x, y)

// Error handling macro
#define OSSL_CHECK_NULL_OR_UNEXPECTED(ptr, msg)                         \
  if ((ptr) == nullptr) {                                               \
    return std::unexpected(std::format("{} {} : {}", __FUNCTION__, msg, \
                                       ERR_error_string(0, nullptr)));  \
  }

#define OSSL_CHECK_OR_UNEXPECTED(good, msg)                             \
  if (good not_eq 1) {                                                  \
    return std::unexpected(std::format("{} {} : {}", __FUNCTION__, msg, \
                                       ERR_error_string(0, nullptr)));  \
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
  if (not(result_name.has_value())) [[likely]] {                            \
    return std::unexpected(std::format("{} {} : {}", __FUNCTION__,          \
                                       result_name.error(),                 \
                                       ERR_error_string(0, nullptr)));      \
  }                                                                         \
  definition = std::move(result_name.value());
#define OSSL_ASSIGN_OR_UNEXPECTED(definition, expression)                   \
  OSSL_ASSIGN_OR_UNEXPECTED_IMPL(                                           \
      ASSIGN_OR_UNEXPECTED_NAME(_error_or_value_, __COUNTER__), definition, \
      expression)

#define ASSIGN_OR_EXIT_IMPL(result_name, definition, expression) \
  auto &&result_name = (expression);                             \
  if (not(result_name.has_value())) [[likely]] {                 \
    std::println("{}", result_name.error());                     \
    exit(1);                                                     \
  }                                                              \
  definition = std::move(result_name.value());

#define ASSIGN_OR_EXIT(definition, expression)                              \
  ASSIGN_OR_EXIT_IMPL(                                                      \
      ASSIGN_OR_UNEXPECTED_NAME(_error_or_value_, __COUNTER__), definition, \
      expression)

using char_unique_ptr = typename std::unique_ptr<char, decltype(&::free)>;
using buf_unique_ptr = typename std::unique_ptr<uint8_t, decltype(&::free)>;

using EVP_PKEY_unique_ptr =
    typename std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EVP_PKEY_CTX_unique_ptr =
    typename std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using EVP_MD_CTX_unique_ptr =
    typename std::unique_ptr<EVP_MD_CTX, decltype(&::EVP_MD_CTX_free)>;
using EVP_MD_unique_ptr =
    typename std::unique_ptr<EVP_MD, decltype(&::EVP_MD_free)>;
using BN_CTX_unique_ptr =
    typename std::unique_ptr<BN_CTX, decltype(&::BN_CTX_free)>;
using BN_unique_ptr = typename std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using EC_GROUP_unique_ptr =
    typename std::unique_ptr<EC_GROUP, decltype(&::EC_GROUP_free)>;
using EC_POINT_unique_ptr =
    typename std::unique_ptr<EC_POINT, decltype(&::EC_POINT_free)>;
using OSSL_LIB_CTX_ptr =
    typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;

inline auto crypto_char_free(void *const ptr) -> void { OPENSSL_free(ptr); }
using CRYPTO_char_unique_ptr =
    typename std::unique_ptr<char, decltype(&crypto::crypto_char_free)>;

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

template <class T>
concept Integral = std::is_integral_v<T>;
template <typename TYPE>
concept StringLike = std::is_convertible_v<TYPE, std::string>;

template <typename VerifierType>
concept VerifierRequest = std::same_as<VerifierType, zerauth::Setup> or
                          std::same_as<VerifierType, zerauth::Proving> or
                          std::same_as<VerifierType, zerauth::Transient>;

template <crypto::VerifierRequest VerifierType>
struct [[nodiscard]] VerifyBuffer_impl;

#define DECLARE_VERIFY_BUFFER_IMPL(Type)                                       \
  template <>                                                                  \
  struct [[nodiscard]] VerifyBuffer_impl<zerauth::Type> {                      \
    static constexpr auto _(flatbuffers::Verifier verifier) noexcept -> bool { \
      return zerauth::Verify##Type##Buffer(verifier);                          \
    }                                                                          \
  };

DECLARE_VERIFY_BUFFER_IMPL(Setup)
DECLARE_VERIFY_BUFFER_IMPL(Proving)
DECLARE_VERIFY_BUFFER_IMPL(Transient)
#undef DECLARE_VERIFY_BUFFER_IMPL

template <crypto::VerifierRequest VerifierType>
[[nodiscard]] auto VerifyBuffer(flatbuffers::Verifier verifier) noexcept
    -> bool {
  return VerifyBuffer_impl<VerifierType>::_(verifier);
}

template bool VerifyBuffer<zerauth::Setup>(flatbuffers::Verifier);
template bool VerifyBuffer<zerauth::Proving>(flatbuffers::Verifier);
template bool VerifyBuffer<zerauth::Transient>(flatbuffers::Verifier);

template <crypto::VerifierRequest VerifierType>
[[nodiscard]] auto flatbuffer_to_struct(std::span<uint8_t const> const &buffer)
    -> std::expected<
        std::invoke_result_t<decltype(&flatbuffers::GetRoot<VerifierType>),
                             void const *>,
        std::string> {
  flatbuffers::Verifier verifier(buffer.data(), buffer.size());

  UNEXPECTED_IF(not VerifyBuffer<VerifierType>(verifier),
                "VerifyBuffer verification failed")

  return flatbuffers::GetRoot<VerifierType>(buffer.data());
}

#define INSTANTIATE_FLATBUFFER_TO_STRUCT(Type)                             \
  template std::expected<                                                  \
      std::invoke_result_t<decltype(&flatbuffers::GetRoot<zerauth::Type>), \
                           void const *>,                                  \
      std::string>                                                         \
  flatbuffer_to_struct<zerauth::Type>(std::span<uint8_t const> const &);

INSTANTIATE_FLATBUFFER_TO_STRUCT(Setup)
INSTANTIATE_FLATBUFFER_TO_STRUCT(Proving)
INSTANTIATE_FLATBUFFER_TO_STRUCT(Transient)

#undef INSTANTIATE_FLATBUFFER_TO_STRUCT

template <crypto::VerifierRequest VerifierType>
[[nodiscard]] auto flatbuffer_to_json(
    std::span<uint8_t const> const &buffer, std::string const &schema_file_name,
    std::vector<std::string> const &include_dirs = {})
    -> std::expected<std::string, std::string> {
  std::string schema_file;

  UNEXPECTED_IF(
      not flatbuffers::LoadFile(schema_file_name.c_str(), false, &schema_file),
      std::format("Failed to load schema file {}", schema_file_name))

  flatbuffers::Parser parser;
  parser.opts.indent_step = 2;  // pretty JSON
  char const **paths_view = (char const **)(include_dirs.data());

  UNEXPECTED_IF(not parser.Parse(schema_file.c_str(), paths_view),
                std::format("Schema parse failed: -- {}", schema_file))
  UNEXPECTED_IF(parser.root_struct_def_ == nullptr,
                "No root type defined in schema")

  flatbuffers::Verifier verifier(buffer.data(), buffer.size());

  UNEXPECTED_IF(not VerifyBuffer<VerifierType>(verifier),
                "VerifyBuffer verification failed")

  std::string json;
  auto const *const err =
      flatbuffers::GenerateText(parser, buffer.data(), &json);

  UNEXPECTED_IF(err not_eq nullptr,
                std::format("Failed to generate JSON {}", err))

  return json;
}

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

auto hex_to_BIGNUM(std::string const &hex_big_num)
    -> std::expected<BN_unique_ptr, std::string> {
  BN_unique_ptr big_number(BN_unique_ptr(BN_new(), ::BN_free));

  BIGNUM *ptr = big_number.get();
  OSSL_CHECK_OR_UNEXPECTED(BN_hex2bn(&ptr, hex_big_num.c_str()) not_eq 0,
                           "Cannot convert hexa string to BIG NUMBER");

  return big_number;
}

auto hex_to_EC_POINT(EC_GROUP_unique_ptr const &group,
                     std::string const &point_hex)
    -> std::expected<EC_POINT_unique_ptr, std::string> {
  EC_POINT_unique_ptr point_ec{EC_POINT_new(group.get()), ::EC_POINT_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      EC_POINT_hex2point(group.get(), point_hex.c_str(), point_ec.get(),
                         nullptr),
      "Cannot convert hexa string to EC_POINT ");

  return point_ec;
}

auto get_ec_group_by_curves_name(std::string const &curve_name)
    -> std::expected<EC_GROUP_unique_ptr, std::string> {
  auto const curve_nid = OBJ_sn2nid(curve_name.c_str());

  UNEXPECTED_IF(curve_nid == NID_undef,

                std::format("Can not find the nid of ({})", curve_name))

  EC_GROUP_unique_ptr ec_group_unique_ptr{EC_GROUP_new_by_curve_name(curve_nid),
                                          ::EC_GROUP_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(
      ec_group_unique_ptr,
      std::format("Can not create group for the nid : ({}) : ", curve_nid));

  return ec_group_unique_ptr;
}

auto get_ec_groups_by_curves_names(std::vector<std::string> const &curves_name)
    -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string> {
  std::vector<EC_GROUP_unique_ptr> ec_group_by_curves_name;

  ec_group_by_curves_name.reserve(curves_name.size());

  for (auto const &curve_name : curves_name) {
    ASSIGN_OR_UNEXPECTED(auto ec_group_unique_ptr,
                         get_ec_group_by_curves_name(curve_name));
    ec_group_by_curves_name.emplace_back(std::move(ec_group_unique_ptr));
  }

  return ec_group_by_curves_name;
}

auto get_ec_groups_by_curves_names(
    flatbuffers::Vector<
        ::flatbuffers::Offset<::flatbuffers::String>> const *const curves_name)
    -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string> {
  std::vector<EC_GROUP_unique_ptr> ec_group_by_curves_name;

  UNEXPECTED_IF(curves_name == nullptr or curves_name->empty(),
                "curves_name is null or empty")

  ec_group_by_curves_name.reserve(curves_name->size());

  for (auto const *const curve_name : *curves_name) {
    ASSIGN_OR_UNEXPECTED(auto ec_group_unique_ptr,
                         get_ec_group_by_curves_name(curve_name->str()));

    ec_group_by_curves_name.emplace_back(std::move(ec_group_unique_ptr));
  }

  return ec_group_by_curves_name;
}

[[nodiscard("Must use base64Decode return value")]]
auto base64Decode(std::string const &b64message) noexcept
    -> std::expected<std::vector<uint8_t>, std::string> {
  std::vector<uint8_t> outbuffer;

  if (b64message.empty()) [[unlikely]] {
    return std::unexpected("base64Decode input: b64message is empty");
  }

  auto calc_decode_length =
      [](std::string const &b64input) -> std::expected<uint64_t, std::string> {
    uint64_t const len{b64input.size()};

    if (len == 0U) [[unlikely]] {
      return std::unexpected("calc_decode_length input: b64input is empty");
    }

    uint64_t const padding(std::count(b64input.end() - 4, b64input.end(), '='));

    return (((len * 3UL) / 4UL) - padding);
  };

  OSSL_ASSIGN_OR_UNEXPECTED(uint64_t const decode_len,
                            calc_decode_length(b64message))

  outbuffer.resize(decode_len + 2UL, '\0');
  if (EVP_DecodeBlock(reinterpret_cast<uint8_t *>(outbuffer.data()),
                      reinterpret_cast<uint8_t const *>(b64message.data()),
                      static_cast<int>(b64message.size())) == -1) [[unlikely]] {
    return std::unexpected(
        std::format("EVP_DecodeBlock not correctly decoded : can not decode "
                    "the base64 of {}",
                    b64message));
  }
  outbuffer.resize(decode_len);
  return outbuffer;
}

[[nodiscard("Must use base64Encode return value")]]
auto base64Encode(std::span<uint8_t const> const &input) noexcept
    -> std::expected<std::string, std::string> {
  std::string outbuffer;

  UNEXPECTED_IF(input.size() == 0U, "base64Encode input: input is empty")

  uint64_t const encoded_size{4UL * ((input.size() + 2UL) / 3UL)};
  outbuffer.resize(encoded_size, '\0');

  using EVP_EncodeBlock_rt =
      std::invoke_result_t<decltype(&EVP_EncodeBlock), unsigned char *,
                           const unsigned char *, int>;

  UNEXPECTED_IF(EVP_EncodeBlock(reinterpret_cast<uint8_t *>(outbuffer.data()),
                                reinterpret_cast<uint8_t const *>(input.data()),
                                static_cast<int>(input.size())) not_eq
                    static_cast<EVP_EncodeBlock_rt>(encoded_size),
                "EVP_EncodeBlock not correctly encoded")

  return outbuffer;
}

template <typename DestType>
struct [[nodiscard]] convert_to_impl;

template <>
struct [[nodiscard]] convert_to_impl<std::vector<std::string>> {
  static constexpr auto _(
      flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
          flat_buffers_vector) noexcept
      -> std::expected<std::vector<std::string>, std::string> {
    std::vector<std::string> container;
    if (flat_buffers_vector not_eq nullptr and
        not flat_buffers_vector->empty()) {
      container.reserve(flat_buffers_vector->size());
      for (auto const *const element : *flat_buffers_vector) {
        container.emplace_back(element->str());
      }
    }
    return container;
  }
};

template <>
struct [[nodiscard]] convert_to_impl<std::vector<EC_GROUP_unique_ptr>> {
  static constexpr auto _(
      flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
          flat_buffers_vector) noexcept
      -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string> {
    std::vector<EC_GROUP_unique_ptr> ec_group_by_curves_name;
    ec_group_by_curves_name.reserve(flat_buffers_vector->size());
    for (auto const *const curve_name : *flat_buffers_vector) {
      auto const curve_nid = OBJ_sn2nid(curve_name->c_str());
      UNEXPECTED_IF(
          curve_nid == NID_undef,
          std::format("Can not find the nid of ({})", curve_name->str()))
      EC_GROUP_unique_ptr ec_group_unique_ptr{
          EC_GROUP_new_by_curve_name(curve_nid), ::EC_GROUP_free};
      OSSL_CHECK_NULL_OR_UNEXPECTED(
          ec_group_unique_ptr,
          std::format("Can not create group for the nid : ({}) : ", curve_nid));
      ec_group_by_curves_name.emplace_back(std::move(ec_group_unique_ptr));
    }
    return ec_group_by_curves_name;
  }
};

template <>
struct [[nodiscard]] convert_to_impl<std::vector<EC_POINT_unique_ptr>> {
  static constexpr auto _(
      flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
          flat_buffers_vector_groups_names,
      flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
          flat_buffers_vector_points) noexcept
      -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string> {
    std::vector<EC_POINT_unique_ptr> ec_points;

    UNEXPECTED_IF(
        flat_buffers_vector_groups_names->size() not_eq
            flat_buffers_vector_points->size(),
        "ec_groups and postulate_random_points do not have the same size")

    ec_points.reserve(flat_buffers_vector_groups_names->size());

    for (auto const [group_name, postulate_random_point] :
         std::ranges::views::zip(*flat_buffers_vector_groups_names,
                                 *flat_buffers_vector_points)) {
      ASSIGN_OR_UNEXPECTED(
          auto const ec_group,
          crypto::get_ec_group_by_curves_name(group_name->str()));

      ASSIGN_OR_UNEXPECTED(
          auto ec_point,
          hex_to_EC_POINT(ec_group, postulate_random_point->str()))

      ec_points.push_back(std::move(ec_point));
    }

    return ec_points;
  }
};

template <typename DestType>
[[nodiscard]] auto convert_to(
    flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
        flat_buffers_vector) noexcept -> std::expected<DestType, std::string> {
  return convert_to_impl<DestType>::_(flat_buffers_vector);
}

template <typename DestType>
[[nodiscard]] auto convert_to(
    flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
        flat_buffers_vector_groups_names,
    flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
        flat_buffers_vector_points) noexcept
    -> std::expected<DestType, std::string> {
  return convert_to_impl<DestType>::_(flat_buffers_vector_groups_names,
                                      flat_buffers_vector_points);
}

auto BIGNUM_to_dec(BN_unique_ptr const &bignumber)
    -> std::expected<std::string const, std::string> {
  OSSL_CHECK_NULL_OR_UNEXPECTED(bignumber,
                                "BIGNUM_to_dec bignumber parameter is null")

  CRYPTO_char_unique_ptr const num_dec_str{BN_bn2dec(bignumber.get()),
                                           crypto::crypto_char_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      num_dec_str, "Cannot convert BIG NUMBER to decimal string : ")

  return std::string{num_dec_str.get(), std::strlen(num_dec_str.get())};
}

auto BIGNUM_to_hex(BN_unique_ptr const &bignumber)
    -> std::expected<std::string const, std::string> {
  CRYPTO_char_unique_ptr const num_hex_str{BN_bn2hex(bignumber.get()),
                                           crypto::crypto_char_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(num_hex_str,
                                "Cannot convert BIG NUMBER to hexa string : ")

  return std::string{num_hex_str.get(), std::strlen(num_hex_str.get())};
}

auto EC_POINT_to_hex(EC_GROUP_unique_ptr const &group,
                     EC_POINT_unique_ptr const &point)
    -> std::expected<std::string, std::string> {
  CRYPTO_char_unique_ptr const point_position_hex_str{
      EC_POINT_point2hex(group.get(), point.get(), POINT_CONVERSION_COMPRESSED,
                         nullptr),
      crypto::crypto_char_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(point_position_hex_str,
                                "Cannot convert EC_POINT to hexa string : ")

  return std::string{point_position_hex_str.get(),
                     std::strlen(point_position_hex_str.get())};
}

auto EC_POINTS_to_hex(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
                      std::vector<EC_POINT_unique_ptr> const &ec_points)
    -> std::expected<std::vector<std::string>, std::string> {
  if (ec_groups.size() not_eq ec_points.size()) {
    std::unexpected("ec_groups and ec_points do not have the same size");
  }
  std::vector<std::string> point_hex;
  point_hex.reserve(ec_groups.size());

  for (auto const &[ec_group, ec_point] :
       std::ranges::views::zip(ec_groups, ec_points)) {
    OSSL_ASSIGN_OR_UNEXPECTED(auto ec_point_to_hex,
                              EC_POINT_to_hex(ec_group, ec_point))
    point_hex.push_back(std::move(ec_point_to_hex));
  }

  return point_hex;
}

// short name in parameter
auto new_ec_group_by_id_curve_name(int const &curve_nid)
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  EC_GROUP_unique_ptr ec_group_unique_ptr{EC_GROUP_new_by_curve_name(curve_nid),
                                          ::EC_GROUP_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(
      ec_group_unique_ptr,
      std::format("Cannot create group for the nid : {} : ", curve_nid));

  return ec_group_unique_ptr;
}

// long name in parameter
template <StringLike StringType>
auto new_ec_group_by_ln_curve_name(StringType const &curve_long_name)
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  int const numerical_identifier{OBJ_ln2nid(curve_long_name)};

  UNEXPECTED_IF(
      numerical_identifier == NID_undef,
      std::format("{} is not a valid curve long name", curve_long_name))

  return new_ec_group_by_id_curve_name(numerical_identifier);
}

// short name in parameter
template <StringLike StringType>
auto new_ec_group_by_sn_curve_name(StringType const &curve_short_name)
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  int const numerical_identifier{OBJ_sn2nid(curve_short_name)};

  UNEXPECTED_IF(
      numerical_identifier == NID_undef,
      std::format("{} is not a valid curve short name.", curve_short_name))

  return new_ec_group_by_id_curve_name(numerical_identifier);
}

auto generate_random_group_scalar(EC_GROUP_unique_ptr const &group)
    -> std::expected<BN_unique_ptr const, std::string> {
  BN_unique_ptr const order{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr random_scalar{BN_unique_ptr(BN_new(), ::BN_free)};

  OSSL_CHECK_NULL_OR_UNEXPECTED(order, "Cannot allocate order : ")
  OSSL_CHECK_NULL_OR_UNEXPECTED(random_scalar,
                                "Cannot allocate random_scalar : ")

  OSSL_CHECK_OR_UNEXPECTED(
      EC_GROUP_get_order(group.get(), order.get(), nullptr),
      "Cannot get group order : ");
  OSSL_CHECK_OR_UNEXPECTED(BN_rand_range(random_scalar.get(), order.get()),
                           "Cannot get random scalar : ");
  return random_scalar;
}

auto generate_random_point(EC_GROUP_unique_ptr const &group)
    -> std::expected<EC_POINT_unique_ptr, std::string> {
  BN_CTX_unique_ptr const ctx{BN_CTX_new(), ::BN_CTX_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(ctx, "Cannot create a BIG NUMBER Context : ")

  EC_POINT const *const generator = EC_GROUP_get0_generator(group.get());
  OSSL_CHECK_NULL_OR_UNEXPECTED(generator, "Cannot get the generator : ")

  EC_POINT_unique_ptr point{EC_POINT_dup(generator, group.get()),
                            ::EC_POINT_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(point, "Cannot allocate a point : ")

  std::expected<BN_unique_ptr const, std::string> const expected_random_scalar{
      generate_random_group_scalar(group)};

  UNEXPECTED_IF(not expected_random_scalar.has_value(),
                expected_random_scalar.error())

  auto &&random_scalar = std::move(expected_random_scalar.value());
  BIGNUM const *const order{EC_GROUP_get0_order(group.get())};
  OSSL_CHECK_NULL_OR_UNEXPECTED(order, "Cannot get order of the curent group ")
  OSSL_CHECK_OR_UNEXPECTED(BN_div(nullptr, random_scalar.get(),
                                  random_scalar.get(), order, ctx.get()),
                           "Cannot process div operation : ");
  OSSL_CHECK_OR_UNEXPECTED(
      EC_POINT_mul(group.get(), point.get(), nullptr, point.get(),
                   random_scalar.get(), nullptr),
      "Cannot process mult operation :");
  return point;
}

auto generate_random_points_from(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups)
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string> {
  std::vector<EC_POINT_unique_ptr> ec_groups_points;
  ec_groups_points.reserve(ec_groups.size());

  for (auto const &ec_group : ec_groups) {
    auto random_point_expected = generate_random_point(ec_group);

    UNEXPECTED_IF(not random_point_expected.has_value(),
                  random_point_expected.error())

    ec_groups_points.emplace_back(std::move(random_point_expected.value()));
  }

  return ec_groups_points;
};

auto hash_to_BIGNUM(std::vector<std::string> const &data)
    -> std::expected<BN_unique_ptr, std::string> {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  EVP_MD_CTX_unique_ptr const mdctx{EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
  EVP_MD_unique_ptr const evp_md{EVP_MD_fetch(nullptr, "SHA256", nullptr),
                                 ::EVP_MD_free};

  OSSL_CHECK_OR_UNEXPECTED(
      EVP_DigestInit_ex(mdctx.get(), evp_md.get(), nullptr),
      "hash_to_BIGNUM EVP_DigestInit_ex fail ");

  for (auto const &secret : data) {
    OSSL_CHECK_OR_UNEXPECTED(
        EVP_DigestUpdate(mdctx.get(), secret.data(), secret.length()),
        "hash_to_BIGNUM EVP_DigestUpdate fail ");
  }

  OSSL_CHECK_OR_UNEXPECTED(
      EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr),
      "hash_to_BIGNUM EVP_DigestFinal_ex fail ");
  BN_unique_ptr hash_number(
      BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, nullptr), ::BN_free);
  OSSL_CHECK_NULL_OR_UNEXPECTED(mdctx, "hash_to_BIGNUM BN_bin2bn fail ")
  return hash_number;
}

// Commitment Registration
auto generate_commitment(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
    BN_unique_ptr const &secret)
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string> {
  UNEXPECTED_IF(
      ec_groups.size() not_eq postulate_random_points.size(),
      "ec_groups and postulate_random_points do not have the same size")

  std::vector<EC_POINT_unique_ptr> commitments;
  commitments.reserve(ec_groups.size());

  for (auto const &[group, postulate_random_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points)) {
    EC_POINT_unique_ptr curve_point{EC_POINT_new(group.get()), ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(group.get(), curve_point.get(), nullptr,
                     postulate_random_point.get(), secret.get(), nullptr),
        "Cannot process mult operation :");
    commitments.emplace_back(std::move(curve_point));
  }
  return commitments;
}

auto generate_transient_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points)
    -> std::expected<
        std::tuple<BN_unique_ptr, std::vector<EC_POINT_unique_ptr>>,
        std::string> {
  UNEXPECTED_IF(
      ec_groups.size() not_eq postulate_random_points.size(),
      "ec_groups and postulate_random_points do not have the same size")

  std::vector<EC_POINT_unique_ptr> transient_points;
  BN_unique_ptr const order_mean{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr const order_length{BN_unique_ptr(BN_new(), ::BN_free)};
  OSSL_CHECK_OR_UNEXPECTED(BN_set_word(order_length.get(), ec_groups.size()),
                           "Bad execution of BN_set_word ");

  for (auto const &[ec_group, postulate_random_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points)) {
    BN_unique_ptr const nonce_group_number{BN_unique_ptr(BN_new(), ::BN_free)};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_GROUP_get_order(ec_group.get(), nonce_group_number.get(), nullptr),
        "ERROR EC_GROUP_get_order")
    OSSL_CHECK_OR_UNEXPECTED(BN_add(order_mean.get(), nonce_group_number.get(),
                                    nonce_group_number.get()),
                             "ERROR BN_add");
  }
  BN_CTX_unique_ptr const bn_ctx{
      BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};

  OSSL_CHECK_OR_UNEXPECTED(BN_div(order_mean.get(), nullptr, order_mean.get(),
                                  order_length.get(), bn_ctx.get()),
                           "Bad execution of BN_div ");

  BN_unique_ptr nonce{BN_unique_ptr(BN_new(), ::BN_free)};
  OSSL_CHECK_OR_UNEXPECTED(BN_rand_range(nonce.get(), order_mean.get()),
                           "Bad execution of BN_rand_range ")

  for (auto const &[ec_group, postulate_random_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points)) {
    EC_POINT_unique_ptr point{EC_POINT_new(ec_group.get()), ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(ec_group.get(), point.get(), nullptr,
                     postulate_random_point.get(), nonce.get(), nullptr),
        "ERROR EC_POINT_mul");
    transient_points.emplace_back(std::move(point));
  }

  return std::make_tuple(std::move(nonce), std::move(transient_points));
}

auto generate_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &commitments,
    std::vector<EC_POINT_unique_ptr> const &transient_points)
    -> std::expected<BN_unique_ptr, std::string> {
  if (ec_groups.size() not_eq commitments.size() and
      transient_points.size() not_eq commitments.size()) {
    return std::unexpected(
        "ec_groups commitments transient_points must have the same size");
  }

  EVP_MD_CTX_unique_ptr const mdctx{EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
  EVP_MD_unique_ptr const evp_md{EVP_MD_fetch(nullptr, "SHA256", nullptr),
                                 ::EVP_MD_free};
  EVP_DigestInit_ex(mdctx.get(), evp_md.get(), nullptr);

  uint8_t *buf = nullptr;
  for (auto const &[group, commitment, transient_point] :
       std::ranges::views::zip(ec_groups, commitments, transient_points)) {
    auto size = EC_POINT_point2buf(group.get(), commitment.get(),
                                   POINT_CONVERSION_COMPRESSED, &buf, nullptr);

    UNEXPECTED_IF(size <= 0, "Can not extract the buffer from point")

    OSSL_CHECK_OR_UNEXPECTED(EVP_DigestUpdate(mdctx.get(), buf, size),
                             "ERROR: EVP_DigestUpdate")

    OPENSSL_secure_clear_free(buf, size);

    size = EC_POINT_point2buf(group.get(), transient_point.get(),
                              POINT_CONVERSION_COMPRESSED, &buf, nullptr);

    UNEXPECTED_IF(size <= 0, "Can not extract the buffer from point")

    OSSL_CHECK_OR_UNEXPECTED(EVP_DigestUpdate(mdctx.get(), buf, size),
                             "ERROR: EVP_DigestUpdate")
    OPENSSL_secure_clear_free(buf, size);
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  OSSL_CHECK_OR_UNEXPECTED(
      EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr),
      "ERROR: EVP_DigestFinal_ex");

  BN_unique_ptr challenge{BN_new(), ::BN_free};
  BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, challenge.get());
  return challenge;
}

auto solve_challenge(BN_unique_ptr const &witness, BN_unique_ptr const &nonce,
                     BN_unique_ptr const &challenge)
    -> std::expected<BN_unique_ptr, std::string> {
  BN_CTX_unique_ptr const bn_ctx(BN_CTX_new(), ::BN_CTX_free);

  BN_unique_ptr response(BN_new(), ::BN_free);

  //  r = (v - (x * c))
  // r_response = (v_commitment - (x_witness * c_challenge))
  OSSL_CHECK_OR_UNEXPECTED(
      BN_mul(response.get(), witness.get(), challenge.get(), bn_ctx.get()),
      "solve_challenge BN_mul error ")
  OSSL_CHECK_OR_UNEXPECTED(BN_sub(response.get(), nonce.get(), response.get()),
                           "solve_challenge BN_sub error ")
  return response;
}

auto solve_challenge(std::string const &secret,
                     std::string const &proving_form_b64)
    -> std::expected<std::string, std::string> {
  ASSIGN_OR_EXIT(auto const buffer_proving_form_bytes,
                 crypto::base64Decode(proving_form_b64))

  ASSIGN_OR_EXIT(
      auto const buffer_proving_form_received,
      flatbuffer_to_struct<zerauth::Proving>(buffer_proving_form_bytes))

  ASSIGN_OR_UNEXPECTED(
      auto const witness,
      crypto::hash_to_BIGNUM(
          {buffer_proving_form_received->salt()->str(), secret}))

  ASSIGN_OR_UNEXPECTED(
      auto const nonce,
      crypto::hex_to_BIGNUM(buffer_proving_form_received->nonce()->str()))

  ASSIGN_OR_UNEXPECTED(
      auto const challenge,
      crypto::hex_to_BIGNUM(buffer_proving_form_received->challenge()->str()))

  ASSIGN_OR_EXIT(auto const response,
                 crypto::solve_challenge(witness, nonce, challenge))

  ASSIGN_OR_EXIT(auto response_hex, crypto::BIGNUM_to_hex(response))

  return response_hex;
}

auto verify(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
            std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
            std::vector<EC_POINT_unique_ptr> const &commitments,
            std::vector<EC_POINT_unique_ptr> const &transient_points,
            BN_unique_ptr const &challenge, BN_unique_ptr const &proof)
    -> std::expected<bool, std::string> {
  for (auto const &[ec_group, postulate_random_point, commitment,
                    transient_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points, commitments,
                               transient_points)) {
    EC_POINT_unique_ptr point_step_one{EC_POINT_new(ec_group.get()),
                                       ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(ec_group.get(), point_step_one.get(), nullptr,
                     postulate_random_point.get(), proof.get(), nullptr),
        "verify EC_POINT_mul error ")
    EC_POINT_unique_ptr point_step_two{EC_POINT_new(ec_group.get()),
                                       ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(ec_group.get(), point_step_two.get(), nullptr,
                     commitment.get(), challenge.get(), nullptr),
        "verify EC_POINT_mul error ")
    EC_POINT_unique_ptr point_step_three{EC_POINT_new(ec_group.get()),
                                         ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_add(ec_group.get(), point_step_three.get(),
                     point_step_one.get(), point_step_two.get(), nullptr),
        "verify EC_POINT_add error ")

    switch (EC_POINT_cmp(ec_group.get(), transient_point.get(),
                         point_step_three.get(), nullptr)) {
      case -1: {
        return std::unexpected("verify EC_POINT_cmp error ");
      }
      // 1 if the points are not equal
      case 1: {
        return false;
      }
      // 0 if the points are equal
      case 0:
        break;

      default:
        break;
    }
  }
  return true;
}

[[nodiscard]]
auto verify(std::string const &proof_hex,
            std::string const &transient_parameter_b64)
    -> std::expected<bool, std::string> {
  ASSIGN_OR_EXIT(auto const transient_parameter_bytes,
                 crypto::base64Decode(transient_parameter_b64))

  ASSIGN_OR_EXIT(auto const buffer_transient_received,
                 crypto::flatbuffer_to_struct<zerauth::Transient>(
                     transient_parameter_bytes))

  ASSIGN_OR_EXIT(auto const proof, hex_to_BIGNUM(proof_hex))

  ASSIGN_OR_EXIT(
      auto const nonce,
      hex_to_BIGNUM(buffer_transient_received->proving()->nonce()->str()))

  ASSIGN_OR_EXIT(
      auto const challenge,
      hex_to_BIGNUM(buffer_transient_received->proving()->challenge()->str()))

  ASSIGN_OR_UNEXPECTED(
      auto const ec_groups,
      crypto::convert_to<std::vector<crypto::EC_GROUP_unique_ptr>>(
          buffer_transient_received->setup()->curve_names()))

  ASSIGN_OR_UNEXPECTED(
      auto const postulate_random_points,
      crypto::convert_to<std::vector<crypto::EC_POINT_unique_ptr>>(
          buffer_transient_received->setup()->curve_names(),
          buffer_transient_received->setup()->postulate_coordinates()))

  ASSIGN_OR_UNEXPECTED(
      auto const commitments,
      crypto::convert_to<std::vector<crypto::EC_POINT_unique_ptr>>(
          buffer_transient_received->setup()->curve_names(),
          buffer_transient_received->setup()->commitment_coordinates()))

  ASSIGN_OR_UNEXPECTED(
      auto const transient_points,
      crypto::convert_to<std::vector<crypto::EC_POINT_unique_ptr>>(
          buffer_transient_received->setup()->curve_names(),
          buffer_transient_received->challenge_coordinates()))

  return verify(ec_groups, postulate_random_points, commitments,
                transient_points, challenge, proof);
}

}  // namespace crypto

[[nodiscard]]
auto flat_buffer_build_transient_builder(
    std::vector<std::string> const &curve_names,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &nonce_hex, std::string const &challenge_hex,
    std::vector<std::string> const &transient_challenge_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  builder.Finish(zerauth::CreateTransient(
      builder,
      zerauth::CreateSetup(
          builder, builder.CreateVectorOfStrings(curve_names),
          builder.CreateVectorOfStrings(postulate_random_points_hex),
          builder.CreateVectorOfStrings(commitments_points_hex),
          builder.CreateString(salt)),
      zerauth::CreateProving(builder, builder.CreateString(nonce_hex.c_str()),
                             builder.CreateString(challenge_hex.c_str())),
      builder.CreateVectorOfStrings(transient_challenge_hex)));
  return builder;
}

[[nodiscard]]
auto flat_buffer_build_setup_builder(
    std::vector<std::string> const &curve_names_selected,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  builder.Finish(zerauth::CreateSetup(
      builder, builder.CreateVectorOfStrings(curve_names_selected),
      builder.CreateVectorOfStrings(postulate_random_points_hex),
      builder.CreateVectorOfStrings(commitments_points_hex),
      builder.CreateString(salt)));

  return builder;
}

[[nodiscard]]
auto flat_buffer_build_proving_builder(std::string const &nonce_hex,
                                       std::string const &challenge_hex,
                                       std::string const &salt) noexcept
    -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  builder.Finish(zerauth::CreateProving(
      builder, builder.CreateString(nonce_hex.c_str()),
      builder.CreateString(challenge_hex.c_str()), builder.CreateString(salt)));
  return builder;
}

[[nodiscard]]
auto list_curve_name() noexcept
    -> std::expected<std::vector<std::string>, std::string> {
  std::vector<std::string> curve_names;

  size_t const curve_name_len = EC_get_builtin_curves(nullptr, 0);

  UNEXPECTED_IF(curve_name_len == 0, "No built-in elliptic curves found.")

  curve_names.reserve(curve_name_len);
  std::vector<EC_builtin_curve> raw_curves(curve_name_len);

  UNEXPECTED_IF(EC_get_builtin_curves(raw_curves.data(), curve_name_len) not_eq
                    curve_name_len,
                "Failed to retrieve built-in curves.")

  for (auto const &curve : raw_curves) {
    auto const nid = curve.nid;
    std::string const long_name(OBJ_nid2ln(nid));

    if (not long_name.empty()) {
      curve_names.emplace_back(long_name);
    }
  }

  return curve_names;
}

auto create_commitment_setup(
    std::string const &secret,
    std::vector<std::string> const &curve_names_selected,
    std::string const &salt = "") -> std::expected<std::string, std::string> {
  ASSIGN_OR_UNEXPECTED(auto const witness,
                       crypto::hash_to_BIGNUM({salt, secret}));

  ASSIGN_OR_UNEXPECTED(
      auto const ec_groups,
      crypto::get_ec_groups_by_curves_names(curve_names_selected));

  ASSIGN_OR_UNEXPECTED(auto const postulate_random_points,
                       crypto::generate_random_points_from(ec_groups));

  ASSIGN_OR_UNEXPECTED(
      auto const commitments,
      crypto::generate_commitment(ec_groups, postulate_random_points, witness))

  ASSIGN_OR_UNEXPECTED(
      auto const postulate_random_points_hex,
      crypto::EC_POINTS_to_hex(ec_groups, postulate_random_points))

  ASSIGN_OR_UNEXPECTED(auto const commitments_points_hex,
                       crypto::EC_POINTS_to_hex(ec_groups, commitments))

  auto const builder_setup = flat_buffer_build_setup_builder(
      curve_names_selected, postulate_random_points_hex, commitments_points_hex,
      salt);

  ASSIGN_OR_UNEXPECTED(auto b64_message,
                       crypto::base64Encode({builder_setup.GetBufferPointer(),
                                             builder_setup.GetSize()}))

  return b64_message;
}

auto create_challenge(std::string const &commitment_setup_b64)
    -> std::expected<std::tuple<std::string, std::string>, std::string> {
  UNEXPECTED_IF(commitment_setup_b64.empty(),
                "create_challenge: commitment_setup_b64 is empty")

  ASSIGN_OR_UNEXPECTED(auto const message_buffer,
                       crypto::base64Decode(commitment_setup_b64))

  ASSIGN_OR_EXIT(auto const buffer_setup_received,
                 crypto::flatbuffer_to_struct<zerauth::Setup>(message_buffer))

  ASSIGN_OR_UNEXPECTED(
      auto const postulate_coordinates,
      crypto::convert_to<std::vector<crypto::EC_POINT_unique_ptr>>(
          buffer_setup_received->curve_names(),
          buffer_setup_received->postulate_coordinates()))

  ASSIGN_OR_UNEXPECTED(
      auto const ec_groups,
      crypto::convert_to<std::vector<crypto::EC_GROUP_unique_ptr>>(
          buffer_setup_received->curve_names()))

  ASSIGN_OR_UNEXPECTED(
      auto const transient_challenge,
      crypto::generate_transient_challenge(ec_groups, postulate_coordinates))

  auto &&[nonce, transient_points] = transient_challenge;

  ASSIGN_OR_UNEXPECTED(
      auto const commitments,
      crypto::convert_to<std::vector<crypto::EC_POINT_unique_ptr>>(
          buffer_setup_received->curve_names(),
          buffer_setup_received->commitment_coordinates()))

  ASSIGN_OR_EXIT(
      auto const challenge,
      crypto::generate_challenge(ec_groups, commitments, transient_points))

  ASSIGN_OR_EXIT(auto const nonce_hex, crypto::BIGNUM_to_hex(nonce))
  ASSIGN_OR_EXIT(auto const challenge_hex, crypto::BIGNUM_to_hex(challenge))

  ASSIGN_OR_EXIT(auto const transient_challenge_hex,
                 crypto::EC_POINTS_to_hex(ec_groups, transient_points))

  auto const builder_proving = flat_buffer_build_proving_builder(
      nonce_hex, challenge_hex, buffer_setup_received->salt()->str());

  ASSIGN_OR_EXIT(auto const curve_names_selected,
                 crypto::convert_to<std::vector<std::string>>(
                     buffer_setup_received->curve_names()))

  ASSIGN_OR_EXIT(auto const postulate_random_points_hex,
                 crypto::convert_to<std::vector<std::string>>(
                     buffer_setup_received->postulate_coordinates()))

  ASSIGN_OR_EXIT(auto const commitments_points_hex,
                 crypto::convert_to<std::vector<std::string>>(
                     buffer_setup_received->commitment_coordinates()))

  auto const builder_transient = flat_buffer_build_transient_builder(
      curve_names_selected, postulate_random_points_hex, commitments_points_hex,
      nonce_hex, challenge_hex, transient_challenge_hex,
      buffer_setup_received->salt()->str());

  ASSIGN_OR_UNEXPECTED(
      auto b64_buffer_transient,
      crypto::base64Encode({builder_transient.GetCurrentBufferPointer(),
                            builder_transient.GetSize()}))

  ASSIGN_OR_UNEXPECTED(
      auto b64_buffer_proving,
      crypto::base64Encode({builder_proving.GetCurrentBufferPointer(),
                            builder_proving.GetSize()}))

  return std::make_tuple(std::move(b64_buffer_proving),
                         std::move(b64_buffer_transient));
}

auto random_curves_selections(size_t const &size) -> std::vector<std::string> {
  std::vector<std::string> curve_names_selected;
  curve_names_selected.reserve(size);
  std::vector<std::string> const curve_names_possible{"secp112r1",
                                                      "secp112r2",
                                                      "secp128r1",
                                                      "secp128r2",
                                                      "secp160k1",
                                                      "secp160r1",
                                                      "secp160r2",
                                                      "secp192k1",
                                                      "secp224k1",
                                                      "secp224r1",
                                                      "secp256k1",
                                                      "secp384r1",
                                                      "secp521r1",
                                                      "prime192v1",
                                                      "prime192v2",
                                                      "prime192v3",
                                                      "prime239v1",
                                                      "prime239v2",
                                                      "prime239v3",
                                                      "prime256v1",
                                                      "sect113r1",
                                                      "sect113r2",
                                                      "sect131r1",
                                                      "sect131r2",
                                                      "sect163k1",
                                                      "sect163r1",
                                                      "sect163r2",
                                                      "sect193r1",
                                                      "sect193r2",
                                                      "sect233k1",
                                                      "sect233r1",
                                                      "sect239k1",
                                                      "sect283k1",
                                                      "sect283r1",
                                                      "sect409k1",
                                                      "sect409r1",
                                                      "sect571k1",
                                                      "sect571r1",
                                                      "c2pnb163v1",
                                                      "c2pnb163v2",
                                                      "c2pnb163v3",
                                                      "c2pnb176v1",
                                                      "c2tnb191v1",
                                                      "c2tnb191v2",
                                                      "c2tnb191v3",
                                                      "c2pnb208w1",
                                                      "c2tnb239v1",
                                                      "c2tnb239v2",
                                                      "c2tnb239v3",
                                                      "c2pnb272w1",
                                                      "c2pnb304w1",
                                                      "c2tnb359v1",
                                                      "c2pnb368w1",
                                                      "c2tnb431r1",
                                                      "wap-wsg-idm-ecid-wtls1",
                                                      "wap-wsg-idm-ecid-wtls3",
                                                      "wap-wsg-idm-ecid-wtls4",
                                                      "wap-wsg-idm-ecid-wtls5",
                                                      "wap-wsg-idm-ecid-wtls6",
                                                      "wap-wsg-idm-ecid-wtls7",
                                                      "wap-wsg-idm-ecid-wtls8",
                                                      "wap-wsg-idm-ecid-wtls9",
                                                      "wap-wsg-idm-ecid-wtls10",
                                                      "wap-wsg-idm-ecid-wtls11",
                                                      "wap-wsg-idm-ecid-wtls12",
                                                      "brainpoolP160r1",
                                                      "brainpoolP160t1",
                                                      "brainpoolP192r1",
                                                      "brainpoolP192t1",
                                                      "brainpoolP224r1",
                                                      "brainpoolP224t1",
                                                      "brainpoolP256r1",
                                                      "brainpoolP256t1",
                                                      "brainpoolP320r1",
                                                      "brainpoolP320t1",
                                                      "brainpoolP384r1",
                                                      "brainpoolP384t1",
                                                      "brainpoolP512r1",
                                                      "brainpoolP512t1"};

  std::random_device random_device;
  std::default_random_engine generator(random_device());

  std::ranges::sample(curve_names_possible.begin(), curve_names_possible.end(),
                      std::back_inserter(curve_names_selected),
                      static_cast<long>(size), generator);

  return curve_names_selected;
}

//
//  openssl ecparam
// -list_curves

// https://eprint.iacr.org/2022/1593.pdf
// http://fc13.ifca.ai/proc/5-1.pdf
// https://sebastiaagramunt.medium.com/discrete-logarithm-problem-and-diffie-hellman-key-exchange-821a45202d26

// https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf
// https://eprint.iacr.org/2022/1593.pdf

// https://datatracker.ietf.org/doc/draft-hao-schnorr/05/
// https://www.rfc-editor.org/rfc/pdfrfc/rfc8235.txt.pdf
// https://asecuritysite.com/zero/dleq_z

// https://github.com/sdiehl/schnorr-nizk
// https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf

#ifdef __EMSCRIPTEN__

using ExpectedStringResult = struct ExpectedStringResult {
  bool is_success;
  std::string value;
  std::string error;
};

auto create_commitment_setup_js(
    std::string const &secret,
    std::vector<std::string> const &curve_names_selected,
    std::string const &salt = "") -> ExpectedStringResult {
  auto const result_or_error =
      create_commitment_setup(secret, curve_names_selected, salt);
  return ExpectedStringResult{.is_success = result_or_error.has_value(),
                              .value = result_or_error.value_or(""),
                              .error = result_or_error.error_or("")};
}

auto solve_challenge_js(std::string const &secret,
                        std::string const &proving_form_b64)
    -> ExpectedStringResult {
  auto const result_or_error =
      crypto::solve_challenge(secret, proving_form_b64);
  return ExpectedStringResult{.is_success = result_or_error.has_value(),
                              .value = result_or_error.value_or(""),
                              .error = result_or_error.error_or("")};
}

using ExpectedBoolResult = struct ExpectedBoolResult {
  bool is_success;
  bool value;
  std::string error;
};

auto verify_js(std::string const &proof_hex,
               std::string const &transient_parameter_b64)
    -> ExpectedBoolResult {
  auto const result_or_error =
      crypto::verify(proof_hex, transient_parameter_b64);
  return ExpectedBoolResult{.is_success = result_or_error.has_value(),
                            .value = result_or_error.value_or(false),
                            .error = result_or_error.error_or("")};
}

using StringPair = struct StringPair {
  std::string first;
  std::string second;
};

using ExpectedTupleStringResult = struct ExpectedTupleStringResult {
  bool is_success;
  StringPair value;
  std::string error;
};

auto create_challenge_js(std::string const &buffer_setup_b64)
    -> ExpectedTupleStringResult {
  auto const result_or_error = create_challenge(buffer_setup_b64);
  auto const [first, second] =
      result_or_error.value_or(std::make_tuple("", ""));
  return ExpectedTupleStringResult{
      .is_success = result_or_error.has_value(),
      .value = StringPair{.first = first, .second = second},
      .error = result_or_error.error_or("")};
}

// Embind allows you to expose C++ functions to JavaScript
EMSCRIPTEN_BINDINGS(my_module) {
  emscripten::value_object<StringPair>("StringPair")
      .field("first", &StringPair::first)
      .field("second", &StringPair::second);
  emscripten::value_object<ExpectedBoolResult>("ExpectedResult")
      .field("isSuccess", &ExpectedBoolResult::is_success)
      .field("value", &ExpectedBoolResult::value)
      .field("error", &ExpectedBoolResult::error);
  emscripten::value_object<ExpectedStringResult>("ExpectedResult")
      .field("isSuccess", &ExpectedStringResult::is_success)
      .field("value", &ExpectedStringResult::value)
      .field("error", &ExpectedStringResult::error);
  emscripten::value_object<ExpectedTupleStringResult>(
      "ExpectedTupleStringResult")
      .field("isSuccess", &ExpectedTupleStringResult::is_success)
      .field("value", &ExpectedTupleStringResult::value)
      .field("error", &ExpectedTupleStringResult::error);
  emscripten::function("generate_random_string",
                       &crypto::generate_random_string);
  emscripten::register_vector<std::string>("StringVector");
  emscripten::function("random_curves_selections", &random_curves_selections);
  emscripten::function("create_commitment_setup", &create_commitment_setup_js);
  emscripten::function("create_challenge", &create_challenge_js);
  emscripten::function("solve_challenge", &solve_challenge_js);
  emscripten::function("verify", &verify_js);
}
#else

auto main(int argc, const char **argv) -> int {
  //  openssl ecparam -list_curves

  /* ================== Enrolement step Start ================== */

#pragma region Setup Enrolement Step

  auto const salt = crypto::generate_random_string(8);

  ASSIGN_OR_EXIT(
      auto const buffer_setup_b64,
      create_commitment_setup("password", random_curves_selections(1), salt));
  // The Prover send to the verifer the postulate and the commitments (in
  // enrolement process) The Verifier generate the transient challenge and
  // send it to the prover

#pragma endregion Setup Enrolement Step

  // Alice ask bob to prove that she knows the password, so bob generate the
  // transient challenge (transient_points) based on the
  // postulate_random_points placed on ther respective eliptic curve group
  // and
  // send the transient nonce to Alice
#pragma region Challenge Step
  // DEBUG
  {
    ASSIGN_OR_EXIT(auto const buffer_setup,
                   crypto::base64Decode(buffer_setup_b64));

    auto const json_setup = crypto::flatbuffer_to_json<zerauth::Setup>(
        buffer_setup, "flatb/setup_phase.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}",
                 json_setup.value_or(json_setup.error()));
  }

  ASSIGN_OR_EXIT(auto const challenge_phase, create_challenge(buffer_setup_b64))

  auto const &[proving_form_b64, transient_parameter_b64] = challenge_phase;

  // DEBUG
  {
    ASSIGN_OR_EXIT(auto const buffer_proving_form,
                   crypto::base64Decode(proving_form_b64));

    auto const json_setup = crypto::flatbuffer_to_json<zerauth::Proving>(
        buffer_proving_form, "flatb/proving_phase.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}",
                 json_setup.value_or(json_setup.error()));
  }

  // DEBUG
  {
    ASSIGN_OR_EXIT(auto const buffer_transient_form,
                   crypto::base64Decode(transient_parameter_b64));

    auto const json_setup = crypto::flatbuffer_to_json<zerauth::Transient>(
        buffer_transient_form, "flatb/transient.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}",
                 json_setup.value_or(json_setup.error()));
  }
#pragma region Challenge Step

#pragma region Solving Step

  ASSIGN_OR_EXIT(auto const proof_hex,
                 crypto::solve_challenge("password", proving_form_b64))
#pragma region Solving Step

  // DEBUG
  {
    std::println("Proof is ({})", proof_hex);
  }

#pragma region Verification Step

  ASSIGN_OR_EXIT(auto const proof,
                 crypto::verify(proof_hex, transient_parameter_b64))

  if (proof) {
    std::println("Alice proved to Bob she knows the password");
  } else {
    std::println("Verification failed");
  }
#pragma region Verification Step

  return 0;
}
#endif