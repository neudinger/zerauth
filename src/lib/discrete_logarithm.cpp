#include "discrete_logarithm.hpp"

#include <flatbuffers/idl.h>       // for Parser, GenerateText
#include <flatbuffers/util.h>      // for LoadFile
#include <flatbuffers/verifier.h>  // for Verifier
#include <openssl/bn.h>            // for BN_new, BN_free
#include <openssl/crypto.h>        // for OPENSSL_secure_clea...
#include <openssl/evp.h>           // for EVP_DigestUpdate
#include <openssl/sha.h>           // for SHA256_DIGEST_LENGTH
#include <openssl/types.h>         // for BIGNUM

#include <algorithm>  // for count
#include <cstring>    // for memcpy, strlen
#include <memory>     // for unique_ptr
#include <random>

#include "flatbuffers/proving_phase_generated.h"  // for Proving, CreateProving
#include "flatbuffers/setup_phase_generated.h"    // for Setup, CreateSetup
#include "flatbuffers/transient_generated.h"      // for Transient, CreateTr...
#include "lib/crypto_tools.hpp"                   // for BN_unique_ptr, EC_P...
#include "lib/macro_tools.hpp"                    // for OSSL_CHECK_OR_UNEXP...
#include <array>                                  // for array

namespace crypto {

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

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
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
    std::vector<std::string> const &include_dirs)
    -> std::expected<std::string, std::string> {
  std::string schema_file;

  UNEXPECTED_IF(
      not flatbuffers::LoadFile(schema_file_name.c_str(), false, &schema_file),
      std::format("Failed to load schema file {}", schema_file_name))

  flatbuffers::Parser parser;
  parser.opts.indent_step = 2;  // pretty JSON

  auto c_include_dirs = include_dirs |
                        std::views::transform([](auto const &data) -> auto {
                          return data.c_str();
                        }) |
                        std::ranges::to<std::vector>();
  c_include_dirs.push_back(nullptr);

  UNEXPECTED_IF(not parser.Parse(schema_file.c_str(), c_include_dirs.data()),
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

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DECLARE_FLATBUFFER_TO_JSON(Type)                 \
  template auto flatbuffer_to_json<zerauth::Type>(       \
      std::span<uint8_t const> const &buffer,            \
      std::string const &schema_file_name,               \
      std::vector<std::string> const &include_dirs = {}) \
      -> std::expected<std::string, std::string>;

DECLARE_FLATBUFFER_TO_JSON(Transient)
DECLARE_FLATBUFFER_TO_JSON(Proving)
DECLARE_FLATBUFFER_TO_JSON(Setup)
#undef DECLARE_FLATBUFFER_TO_JSON

[[nodiscard("Must use base64Decode return value")]]
auto base64Decode(std::string const &b64message) noexcept
    -> std::expected<std::vector<uint8_t>, std::string> {
  std::vector<uint8_t> outbuffer{};

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
  if (EVP_DecodeBlock(
          static_cast<uint8_t *>(outbuffer.data()),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

  UNEXPECTED_IF(input.empty(), "base64Encode input: input is empty")

  uint64_t const encoded_size{4UL * ((input.size() + 2UL) / 3UL)};
  outbuffer.resize(encoded_size, '\0');

  using EVP_EncodeBlock_rt =
      std::invoke_result_t<decltype(&EVP_EncodeBlock), unsigned char *,
                           const unsigned char *, int>;

  UNEXPECTED_IF(
      EVP_EncodeBlock(
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<uint8_t *>(outbuffer.data()),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<uint8_t const *>(input.data()),
          static_cast<int>(input.size())) not_eq
          static_cast<EVP_EncodeBlock_rt>(encoded_size),
      "EVP_EncodeBlock not correctly encoded")

  return outbuffer;
}

[[nodiscard("Must use the decimal string return value"), maybe_unused]]
auto BIGNUM_to_dec(BN_unique_ptr const &bignumber) noexcept
    -> std::expected<std::string const, std::string> {
  OSSL_CHECK_NULL_OR_UNEXPECTED(bignumber,
                                "BIGNUM_to_dec bignumber parameter is null")

  CRYPTO_char_unique_ptr const num_dec_str{BN_bn2dec(bignumber.get()),
                                           crypto::crypto_char_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      num_dec_str, "Cannot convert BIG NUMBER to decimal string : ")

  return std::string{num_dec_str.get(), std::strlen(num_dec_str.get())};
}

[[nodiscard("Must use the hexadecimal string return value"), maybe_unused]]
auto BIGNUM_to_hex(BN_unique_ptr const &bignumber) noexcept
    -> std::expected<std::string const, std::string> {
  CRYPTO_char_unique_ptr const num_hex_str{BN_bn2hex(bignumber.get()),
                                           crypto::crypto_char_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(num_hex_str,
                                "Cannot convert BIG NUMBER to hexa string : ")

  return std::string{num_hex_str.get(), std::strlen(num_hex_str.get())};
}

[[nodiscard("Must use the hexadecimal string return value")]]
auto EC_POINT_to_hex(EC_GROUP_unique_ptr const &group,
                     EC_POINT_unique_ptr const &point) noexcept
    -> std::expected<std::string, std::string> {
  OSSL_CHECK_NULL_OR_UNEXPECTED(group, "group parameter is null")
  OSSL_CHECK_NULL_OR_UNEXPECTED(point, "point parameter is null")
  CRYPTO_char_unique_ptr const point_position_hex_str{
      EC_POINT_point2hex(group.get(), point.get(), POINT_CONVERSION_COMPRESSED,
                         nullptr),
      crypto::crypto_char_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(point_position_hex_str,
                                "Cannot convert EC_POINT to hexa string : ")

  return std::string{point_position_hex_str.get(),
                     std::strlen(point_position_hex_str.get())};
}

[[nodiscard("Must use hex_to_BIGNUM return value")]]
auto hex_to_BIGNUM(std::string const &hex_big_num) noexcept
    -> std::expected<BN_unique_ptr, std::string> {
  BN_unique_ptr big_number(BN_unique_ptr(BN_new(), ::BN_free));

  OSSL_CHECK_NULL_OR_UNEXPECTED(big_number, "Cannot allocate BIGNUM")

  BIGNUM *ptr = big_number.get();
  OSSL_CHECK_OR_UNEXPECTED(BN_hex2bn(&ptr, hex_big_num.c_str()) not_eq 0,
                           "Cannot convert hexa string to BIG NUMBER");

  return big_number;
}

[[nodiscard("Must use hex_to_EC_POINT return value")]]
auto hex_to_EC_POINT(EC_GROUP_unique_ptr const &group,
                     std::string const &point_hex) noexcept
    -> std::expected<EC_POINT_unique_ptr, std::string> {
  EC_POINT_unique_ptr point_ec{EC_POINT_new(group.get()), ::EC_POINT_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      EC_POINT_hex2point(group.get(), point_hex.c_str(), point_ec.get(),
                         nullptr),
      "Cannot convert hexa string to EC_POINT ");

  return point_ec;
}

[[nodiscard("Must use the hexadecimal string array return value")]]
auto EC_POINTS_to_hex(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &ec_points) noexcept
    -> std::expected<std::vector<std::string>, std::string> {
  if (ec_groups.size() not_eq ec_points.size()) {
    return std::unexpected("ec_groups and ec_points do not have the same size");
  }
  std::vector<std::string> points_hex;
  points_hex.reserve(ec_groups.size());

  for (auto const &[ec_group, ec_point] :
       std::ranges::views::zip(ec_groups, ec_points)) {
    OSSL_ASSIGN_OR_UNEXPECTED(auto ec_point_to_hex,
                              EC_POINT_to_hex(ec_group, ec_point))
    points_hex.push_back(std::move(ec_point_to_hex));
  }
  return points_hex;
}

[[nodiscard("Must use get_ec_group_by_curves_name return value")]]
auto get_ec_group_by_curves_name(std::string const &curve_name) noexcept
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

[[nodiscard("Must use get_ec_groups_by_curves_names return value")]]
auto get_ec_groups_by_curves_names(
    std::vector<std::string> const &curves_name) noexcept
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

[[nodiscard("Must use get_ec_groups_by_curves_names return value")]]
auto get_ec_groups_by_curves_names(
    flatbuffers::Vector<
        ::flatbuffers::Offset<::flatbuffers::String>> const *const
        curves_name) noexcept
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

[[nodiscard("Must use the returned EC_GROUP_unique_ptr"), maybe_unused]]
auto new_ec_group_by_id_curve_name(int const &curve_nid) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  EC_GROUP_unique_ptr ec_group_unique_ptr{EC_GROUP_new_by_curve_name(curve_nid),
                                          ::EC_GROUP_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(
      ec_group_unique_ptr,
      std::format("Cannot create group for the nid : {} : ", curve_nid));

  return ec_group_unique_ptr;
}

[[nodiscard("Must use the returned EC_GROUP_unique_ptr"), maybe_unused]]
auto new_ec_group_by_ln_curve_name(std::string const &curve_long_name) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  int const numerical_identifier{OBJ_ln2nid(curve_long_name.c_str())};

  UNEXPECTED_IF(
      numerical_identifier == NID_undef,
      std::format("{} is not a valid curve long name", curve_long_name))

  return new_ec_group_by_id_curve_name(numerical_identifier);
}

auto new_ec_group_by_sn_curve_name(std::string const &curve_short_name) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  int const numerical_identifier{OBJ_sn2nid(curve_short_name.c_str())};

  UNEXPECTED_IF(
      numerical_identifier == NID_undef,
      std::format("{} is not a valid curve short name.", curve_short_name))

  return new_ec_group_by_id_curve_name(numerical_identifier);
}

[[nodiscard]]
auto generate_random_group_scalar(EC_GROUP_unique_ptr const &group) noexcept
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

[[nodiscard]]
auto generate_random_point(EC_GROUP_unique_ptr const &group) noexcept
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
  OSSL_CHECK_NULL_OR_UNEXPECTED(order, "Cannot get order of the current group ")
  OSSL_CHECK_OR_UNEXPECTED(BN_div(nullptr, random_scalar.get(),
                                  random_scalar.get(), order, ctx.get()),
                           "Cannot process div operation : ");
  OSSL_CHECK_OR_UNEXPECTED(
      EC_POINT_mul(group.get(), point.get(), nullptr, point.get(),
                   random_scalar.get(), nullptr),
      "Cannot process mult operation :");
  return point;
}

[[nodiscard]]
auto generate_random_points_from(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups) noexcept
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

[[nodiscard]]
auto hash_to_BIGNUM(std::vector<std::string> const &data) noexcept
    -> std::expected<BN_unique_ptr, std::string> {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash{};
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

[[nodiscard]]
auto generate_commitment(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
    BN_unique_ptr const &secret) noexcept
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

[[nodiscard]]
auto generate_transient_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points) noexcept
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

[[nodiscard]]
auto generate_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &commitments,
    std::vector<EC_POINT_unique_ptr> const &transient_points) noexcept
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

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash{};
  OSSL_CHECK_OR_UNEXPECTED(
      EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr),
      "ERROR: EVP_DigestFinal_ex");

  BN_unique_ptr challenge{BN_new(), ::BN_free};
  BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, challenge.get());
  return challenge;
}

[[nodiscard]]
auto verify(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
            std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
            std::vector<EC_POINT_unique_ptr> const &commitments,
            std::vector<EC_POINT_unique_ptr> const &transient_points,
            BN_unique_ptr const &challenge, BN_unique_ptr const &proof) noexcept
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
      default:
        break;
    }
  }
  return true;
}

[[nodiscard]]
auto solve_challenge(BN_unique_ptr const &witness, BN_unique_ptr const &nonce,
                     BN_unique_ptr const &challenge) noexcept
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

[[nodiscard]]
auto solve_challenge(SolveChallengeParams const &params) noexcept
    -> std::expected<std::string, std::string> {
  ASSIGN_OR_UNEXPECTED(auto const buffer_proving_form_bytes,
                       crypto::base64Decode(params.proving_form_b64))

  ASSIGN_OR_UNEXPECTED(
      auto const buffer_proving_form_received,
      flatbuffer_to_struct<zerauth::Proving>(buffer_proving_form_bytes))

  ASSIGN_OR_UNEXPECTED(
      auto const witness,
      crypto::hash_to_BIGNUM(
          {buffer_proving_form_received->salt()->str(), params.secret}))

  ASSIGN_OR_UNEXPECTED(
      auto const nonce,
      crypto::hex_to_BIGNUM(buffer_proving_form_received->nonce()->str()))

  ASSIGN_OR_UNEXPECTED(
      auto const challenge,
      crypto::hex_to_BIGNUM(buffer_proving_form_received->challenge()->str()))

  ASSIGN_OR_UNEXPECTED(auto const response,
                       crypto::solve_challenge(witness, nonce, challenge))

  ASSIGN_OR_UNEXPECTED(auto response_hex, crypto::BIGNUM_to_hex(response))

  return response_hex;
}

[[nodiscard]]
auto verify(VerifyParams const &params) noexcept
    -> std::expected<bool, std::string> {
  ASSIGN_OR_UNEXPECTED(auto const transient_parameter_bytes,
                       crypto::base64Decode(params.transient_parameter_b64))

  ASSIGN_OR_UNEXPECTED(auto const buffer_transient_received,
                       crypto::flatbuffer_to_struct<zerauth::Transient>(
                           transient_parameter_bytes))

  ASSIGN_OR_UNEXPECTED(auto const proof, hex_to_BIGNUM(params.proof_hex))

  ASSIGN_OR_UNEXPECTED(
      auto const nonce,
      hex_to_BIGNUM(buffer_transient_received->proving()->nonce()->str()))

  ASSIGN_OR_UNEXPECTED(
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

[[nodiscard("Must use the returned list of curve names"), maybe_unused]]
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
    std::string const long_name(OBJ_nid2ln(curve.nid));

    if (not long_name.empty()) {
      curve_names.emplace_back(long_name);
    }
  }

  return curve_names;
}

[[nodiscard]]
auto create_challenge(std::string const &commitment_setup_b64) noexcept
    -> std::expected<std::tuple<std::string, std::string>, std::string> {
  UNEXPECTED_IF(commitment_setup_b64.empty(),
                "create_challenge: commitment_setup_b64 is empty")

  ASSIGN_OR_UNEXPECTED(auto const message_buffer,
                       crypto::base64Decode(commitment_setup_b64))

  ASSIGN_OR_UNEXPECTED(
      auto const buffer_setup_received,
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

  ASSIGN_OR_UNEXPECTED(
      auto const challenge,
      crypto::generate_challenge(ec_groups, commitments, transient_points))

  ASSIGN_OR_UNEXPECTED(auto const nonce_hex, crypto::BIGNUM_to_hex(nonce))
  ASSIGN_OR_UNEXPECTED(auto const challenge_hex,
                       crypto::BIGNUM_to_hex(challenge))

  ASSIGN_OR_UNEXPECTED(auto const transient_challenge_hex,
                       crypto::EC_POINTS_to_hex(ec_groups, transient_points))

  auto const builder_proving = flatbuffer_build_proving_builder(
      {.nonce_hex = nonce_hex,
       .challenge_hex = challenge_hex,
       .salt = buffer_setup_received->salt()->str()});

  ASSIGN_OR_UNEXPECTED(auto const curve_names_selected,
                       crypto::convert_to<std::vector<std::string>>(
                           buffer_setup_received->curve_names()))

  ASSIGN_OR_UNEXPECTED(auto const postulate_random_points_hex,
                       crypto::convert_to<std::vector<std::string>>(
                           buffer_setup_received->postulate_coordinates()))

  ASSIGN_OR_UNEXPECTED(auto const commitments_points_hex,
                       crypto::convert_to<std::vector<std::string>>(
                           buffer_setup_received->commitment_coordinates()))

  auto const builder_transient = flatbuffer_build_transient_builder(
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

[[nodiscard]]
auto create_commitment_setup(
    std::string const &secret,
    std::vector<std::string> const &curve_names_selected,
    std::string const &salt) noexcept
    -> std::expected<std::string, std::string> {
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

  auto const builder_setup = flatbuffer_build_setup_builder(
      curve_names_selected, postulate_random_points_hex, commitments_points_hex,
      salt);

  ASSIGN_OR_UNEXPECTED(auto b64_message,
                       crypto::base64Encode({builder_setup.GetBufferPointer(),
                                             builder_setup.GetSize()}))

  return b64_message;
}

template <crypto::IsStringContainer StringContainer>
[[nodiscard]]
auto random_curves_selections(
    size_t size, StringContainer const &possible_curve_names) noexcept
    -> std::vector<std::string> {
  std::vector<std::string_view> curve_names_selected;
  curve_names_selected.reserve(size);

  std::random_device random_device;
  std::default_random_engine generator(random_device());

  std::ranges::sample(possible_curve_names.begin(), possible_curve_names.end(),
                      std::back_inserter(curve_names_selected), size,
                      generator);

  return {curve_names_selected.begin(), curve_names_selected.end()};
}

template auto random_curves_selections(
    size_t size = 1,
    std::initializer_list<std::string_view> const &possible_curve_names =
        all_possible_curve_names) -> std::vector<std::string>;

template auto random_curves_selections(
    size_t size, std::vector<std::string> const &possible_curve_names)
    -> std::vector<std::string>;

}  // namespace crypto

[[nodiscard]]
auto flatbuffer_build_transient_builder(
    std::vector<std::string> const &curve_names,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &nonce_hex, std::string const &challenge_hex,
    std::vector<std::string> const &transient_challenge_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  auto const curve_names_vec = builder.CreateVectorOfStrings(curve_names);
  auto const postulate_vec =
      builder.CreateVectorOfStrings(postulate_random_points_hex);
  auto const commitments_vec =
      builder.CreateVectorOfStrings(commitments_points_hex);
  auto const salt_str = builder.CreateString(salt);

  auto const setup_offset = zerauth::CreateSetup(
      builder, curve_names_vec, postulate_vec, commitments_vec, salt_str);

  auto const proving_offset =
      zerauth::CreateProving(builder, builder.CreateString(nonce_hex.c_str()),
                             builder.CreateString(challenge_hex.c_str()));

  auto const transient_challenge_vec =
      builder.CreateVectorOfStrings(transient_challenge_hex);

  builder.Finish(zerauth::CreateTransient(builder, setup_offset, proving_offset,
                                          transient_challenge_vec));

  return builder;
}

[[nodiscard]]
auto flatbuffer_build_setup_builder(
    std::vector<std::string> const &curve_names_selected,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  if (curve_names_selected.empty() or postulate_random_points_hex.empty() or
      commitments_points_hex.empty()) {
    return builder;
  }
  auto create_fb_vector = [&](const std::vector<std::string> &src_vector)
      -> flatbuffers::Offset<
          flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>> {
    std::vector<flatbuffers::Offset<flatbuffers::String>> offsets;
    offsets.reserve(src_vector.size());
    for (auto const &element : src_vector) {
      offsets.push_back(builder.CreateString(element));
    }
    return builder.CreateVector(offsets);
  };

  auto const curve_names_vec = create_fb_vector(curve_names_selected);
  auto const postulate_vec = create_fb_vector(postulate_random_points_hex);
  auto const commitments_vec = create_fb_vector(commitments_points_hex);
  auto const salt_str = builder.CreateString(salt);

  auto const setup_offset = zerauth::CreateSetup(
      builder, curve_names_vec, postulate_vec, commitments_vec, salt_str);

  builder.Finish(setup_offset);

  return builder;
}

[[nodiscard]]
auto flatbuffer_build_proving_builder(ProvingParams const &params) noexcept
    -> flatbuffers::FlatBufferBuilder {
  flatbuffers::FlatBufferBuilder builder;

  auto const nonce_str = builder.CreateString(params.nonce_hex.c_str());
  auto const challenge_str = builder.CreateString(params.challenge_hex.c_str());
  auto const salt_str = builder.CreateString(params.salt.c_str());

  auto const proving_offset =
      zerauth::CreateProving(builder, nonce_str, challenge_str, salt_str);

  builder.Finish(proving_offset);
  return builder;
}
