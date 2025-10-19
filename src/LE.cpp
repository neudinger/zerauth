#include <sys/types.h>

#include <expected>
#include <format>
#include <ranges>

#include <flatbuffers/flatbuffer_builder.h>
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

#include <print>  // C++23 header for std::println

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "flatbuffer/commitment_generated.h"
#include <array>
#include <bit>
#include <forward_list>
#include <ios>
#include <span>
#include <stddef.h>
#include <stdlib.h>
#include <type_traits>

void printEC_POINT(const EC_GROUP *group, const char *msg,
                   const EC_POINT *point) {
  char *point_str =
      EC_POINT_point2hex(group, point, POINT_CONVERSION_COMPRESSED, nullptr);
  std::cout << msg << ": " << std::hex << point_str << std::endl;
  OPENSSL_free(point_str);
}

// Helper function to print BIGNUM values in hexadecimal
void printBN(char const *msg, BIGNUM const *bn) {
  char *num_str = BN_bn2hex(bn);
  char *result_str = BN_bn2dec(bn);  // Convert the result to a decimal string

  std::cout << msg << ": " << num_str << " : " << result_str << std::endl;
  OPENSSL_free(num_str);
  OPENSSL_free(result_str);
}

namespace crypto {

#define XSTR(s) STR(s)
#define STR(s) #s

#define EXPAND(x) x
#define STRINGIFY(x) #x
#define CONCAT(x, y) x##y

// Error handling macro
#define OSSL_CHECK_NULL_OR_UNEXPECTED(ptr, msg)                     \
  if ((ptr) == nullptr) {                                           \
    return std::unexpected(                                         \
        std::format("{} : {}", msg, ERR_error_string(0, nullptr))); \
  }

#define OSSL_CHECK_OR_UNEXPECTED(good, msg)                         \
  if (good not_eq 1) {                                              \
    return std::unexpected(                                         \
        std::format("{} : {}", msg, ERR_error_string(0, nullptr))); \
  }

#define ASSIGN_OR_UNEXPECTED_NAME(x, y) CONCAT(x, y)
#define ASSIGN_OR_UNEXPECTED_IMPL(result_name, definition, expression) \
  auto const &result_name = (expression);                              \
  if (not(result_name.has_value())) [[likely]] {                       \
    return std::unexpected(std::format("{} : {}", result_name.error(), \
                                       ERR_error_string(0, nullptr))); \
  }                                                                    \
  definition = result_name.value();
#define ASSIGN_OR_UNEXPECTED(definition, expression)                        \
  ASSIGN_OR_UNEXPECTED_IMPL(                                                \
      ASSIGN_OR_UNEXPECTED_NAME(_error_or_value_, __COUNTER__), definition, \
      expression)

using namespace std::literals;
using namespace std::string_literals;
using namespace std::string_view_literals;

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

inline auto crypto_char_free(void *const ptr) -> void { OPENSSL_free(ptr); }
using CRYPTO_char_unique_ptr =
    typename std::unique_ptr<char, decltype(&crypto::crypto_char_free)>;

template <class T>
concept Integral = std::is_integral_v<T>;
template <typename TYPE>
concept StringLike = std::is_convertible_v<TYPE, std::string>;

// using BN_unique_ptr =
// typename std::unique_ptr<BIGNUM, decltype(&::BN_free)>;

auto get_ec_group_by_curves_name(std::vector<std::string> const &curves_name)
    -> std::expected<std::vector<EC_GROUP_unique_ptr> const, std::string> {
  std::vector<EC_GROUP_unique_ptr> ec_group_by_curves_name;
  ec_group_by_curves_name.reserve(curves_name.size());
  for (auto const &curve_name : curves_name) {
    auto curve_nid = OBJ_sn2nid(curve_name.c_str());
    if (curve_nid == NID_undef) {
      return std::unexpected(
          std::format("Can not find the nid of ({})", curve_name));
    }
    EC_GROUP_unique_ptr ec_group_unique_ptr{
        EC_GROUP_new_by_curve_name(curve_nid), ::EC_GROUP_free};
    OSSL_CHECK_NULL_OR_UNEXPECTED(
        ec_group_unique_ptr,
        std::format("Can not create group for the nid : {} : ", curve_nid));
    ec_group_by_curves_name.emplace_back(std::move(ec_group_unique_ptr));
  }
  return ec_group_by_curves_name;
}

auto BIGNUM_to_dec(BN_unique_ptr const &bignumber)
    -> std::expected<std::string const, std::string> {
  CRYPTO_char_unique_ptr const num_dec_str{BN_bn2dec(bignumber.get()),
                                           crypto::crypto_char_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      num_dec_str, "Cannot convert BIG NUMBER to decimal string : "sv)

  return std::string{num_dec_str.get(), std::strlen(num_dec_str.get())};
}

auto BIGNUM_to_hex(BN_unique_ptr const &bignumber)
    -> std::expected<std::string const, std::string> {
  CRYPTO_char_unique_ptr const num_hex_str{BN_bn2hex(bignumber.get()),
                                           crypto::crypto_char_free};
  // BN_hex2bn(BIGNUM **a, const char *str);
  OSSL_CHECK_NULL_OR_UNEXPECTED(num_hex_str,
                                "Cannot convert BIG NUMBER to hexa string : "sv)

  return std::string{num_hex_str.get(), std::strlen(num_hex_str.get())};
}

auto EC_POINT_to_hex(
    std::tuple<EC_GROUP_unique_ptr, EC_POINT_unique_ptr> const &group_point)
    -> std::expected<std::string const, std::string> {
  auto const &[group, point]{group_point};

  CRYPTO_char_unique_ptr const point_position_hex_str{
      EC_POINT_point2hex(group.get(), point.get(), POINT_CONVERSION_COMPRESSED,
                         nullptr),
      crypto::crypto_char_free};
  // EC_POINT_hex2point()
  // EC_POINT_hex2point(const EC_GROUP *, const char *, EC_POINT *, BN_CTX *)
  OSSL_CHECK_NULL_OR_UNEXPECTED(point_position_hex_str,
                                "Cannot convert EC_POINT to hexa string : "sv)

  return std::string{point_position_hex_str.get(),
                     std::strlen(point_position_hex_str.get())};
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
  if (numerical_identifier == NID_undef) {
    return std::unexpected(
        std::format("{} is not a valid curve long name", curve_long_name));
  }
  return new_ec_group_by_id_curve_name(numerical_identifier);
}

// short name in parameter
template <StringLike StringType>
auto new_ec_group_by_sn_curve_name(StringType const &curve_short_name)
    -> std::expected<EC_GROUP_unique_ptr const, std::string> {
  int const numerical_identifier{OBJ_sn2nid(curve_short_name)};
  if (numerical_identifier == NID_undef) {
    return std::unexpected(
        std::format("{} is not a valid curve short name.", curve_short_name));
  }
  return new_ec_group_by_id_curve_name(numerical_identifier);
}

auto generate_random_group_scalar(EC_GROUP_unique_ptr const &group)
    -> std::expected<BN_unique_ptr const, std::string> {
  BN_unique_ptr const order{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr random_scalar{BN_unique_ptr(BN_new(), ::BN_free)};

  OSSL_CHECK_NULL_OR_UNEXPECTED(order, "Cannot allocate order : "sv)
  OSSL_CHECK_NULL_OR_UNEXPECTED(random_scalar,
                                "Cannot allocate random_scalar : "sv)

  OSSL_CHECK_OR_UNEXPECTED(
      EC_GROUP_get_order(group.get(), order.get(), nullptr),
      "Cannot get group order : "sv);
  OSSL_CHECK_OR_UNEXPECTED(BN_rand_range(random_scalar.get(), order.get()),
                           "Cannot get random scalar : "sv);
  return random_scalar;
}

auto generate_random_groups_scalar(
    std::tuple<EC_GROUP_unique_ptr const, EC_GROUP_unique_ptr const> const
        &groups) -> std::expected<BN_unique_ptr const, std::string> {
  auto const &[group_g, group_h]{groups};
  BN_CTX_unique_ptr bn_ctx{BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};
  BN_unique_ptr order_mean{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr order_g{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr order_h{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr order_length{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_unique_ptr random_scalar{BN_unique_ptr(BN_new(), ::BN_free)};

  OSSL_CHECK_OR_UNEXPECTED(BN_dec2bn((BIGNUM **)&(*order_length), "2"),
                           "Cannot convert decimal string to BIG NUMBER"sv)

  OSSL_CHECK_OR_UNEXPECTED(
      EC_GROUP_get_order(group_g.get(), order_g.get(), nullptr),
      "Can not get order of group g : "sv);
  OSSL_CHECK_OR_UNEXPECTED(
      EC_GROUP_get_order(group_h.get(), order_h.get(), nullptr),
      "Can not get order of group h : "sv);
  OSSL_CHECK_OR_UNEXPECTED(
      BN_add(order_mean.get(), order_h.get(), order_h.get()),
      "Can not execute add operation : "sv);
  OSSL_CHECK_OR_UNEXPECTED(BN_div(order_mean.get(), nullptr, order_mean.get(),
                                  order_length.get(), bn_ctx.get()),
                           "Can not execute division operation : "sv);
  OSSL_CHECK_OR_UNEXPECTED(BN_rand_range(random_scalar.get(), order_mean.get()),
                           "Can not execute random range operation : "sv);
  return random_scalar;
}

auto generate_random_point(EC_GROUP_unique_ptr const &group)
    -> std::expected<EC_POINT_unique_ptr, std::string> {
  BN_CTX_unique_ptr const ctx{BN_CTX_new(), ::BN_CTX_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(ctx, "Cannot create a BIG NUMBER Context : "sv)

  EC_POINT const *const generator = EC_GROUP_get0_generator(group.get());
  OSSL_CHECK_NULL_OR_UNEXPECTED(generator, "Cannot get the generator : "sv)

  EC_POINT_unique_ptr point{EC_POINT_dup(generator, group.get()),
                            ::EC_POINT_free};
  OSSL_CHECK_NULL_OR_UNEXPECTED(point, "Cannot allocate a point : "sv)

  std::expected<BN_unique_ptr const, std::string> const expected_random_scalar{
      generate_random_group_scalar(group)};
  if (not expected_random_scalar.has_value()) {
    return std::unexpected(expected_random_scalar.error());
  }
  auto &&random_scalar = std::move(expected_random_scalar.value());
  BIGNUM const *const order{EC_GROUP_get0_order(group.get())};
  OSSL_CHECK_NULL_OR_UNEXPECTED(order,
                                "Cannot get order of the curent group "sv)
  OSSL_CHECK_OR_UNEXPECTED(BN_div(nullptr, random_scalar.get(),
                                  random_scalar.get(), order, ctx.get()),
                           "Cannot process div operation : "sv);
  OSSL_CHECK_OR_UNEXPECTED(
      EC_POINT_mul(group.get(), point.get(), nullptr, point.get(),
                   random_scalar.get(), nullptr),
      "Cannot process mult operation :"sv);
  return point;
}

auto generate_random_points_from(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups)
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string> {
  std::vector<EC_POINT_unique_ptr> ec_groups_points;
  ec_groups_points.reserve(ec_groups.size());

  for (auto const &ec_group : ec_groups) {
    auto random_point_expected = generate_random_point(ec_group);
    if (not random_point_expected.has_value()) {
      return std::unexpected(random_point_expected.error());
    }
    ec_groups_points.emplace_back(std::move(random_point_expected.value()));
  }

  return ec_groups_points;
};

auto hash_to_BIGNUM(std::vector<std::string> const &data) -> BN_unique_ptr {
  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  EVP_MD_CTX_unique_ptr const mdctx{EVP_MD_CTX_new(), ::EVP_MD_CTX_free};
  // OSSL_CHECK_NULL_OR_UNEXPECTED(mdctx, ""sv)

  EVP_MD_unique_ptr const evp_md{EVP_MD_fetch(nullptr, "SHA256", nullptr),
                                 ::EVP_MD_free};
  // OSSL_CHECK_NULL_OR_UNEXPECTED(mdctx, ""sv)

  EVP_DigestInit_ex(mdctx.get(), evp_md.get(), nullptr);

  for (auto const &secret : data) {
    EVP_DigestUpdate(mdctx.get(), secret.data(), secret.length());
  }

  EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr);
  // OSSL_CHECK_OR_UNEXPECTED(EVP_DigestFinal_ex(mdctx.get(), hash.data(),
  // nullptr), msg)
  BN_unique_ptr hash_number{BN_unique_ptr(
      BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, nullptr), ::BN_free)};
  // OSSL_CHECK_NULL_OR_UNEXPECTED(x_secret, ""sv)

  // assert(BN_div(nullptr, x_secret, x_secret, order, ctx) == 1);
  return hash_number;
}

// Commitment Registration
auto generate_commitment(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
    BN_unique_ptr const &secret)
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string> {
  if (ec_groups.size() not_eq postulate_random_points.size()) {
    std::unexpected(
        "ec_groups and postulate_random_points do not have the same size");
  }

  std::vector<EC_POINT_unique_ptr> commitments;
  commitments.reserve(ec_groups.size());

  for (auto const &[group, postulate_random_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points)) {
    EC_POINT_unique_ptr curve_point{EC_POINT_new(group.get()), ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(group.get(), curve_point.get(), nullptr,
                     postulate_random_point.get(), secret.get(), nullptr),
        "Cannot process mult operation :"sv);
    commitments.emplace_back(std::move(curve_point));
  }
  return commitments;
}

auto generate_transient_chalenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points)
    -> std::expected<
        std::tuple<BN_unique_ptr, std::vector<EC_POINT_unique_ptr>>,
        std::string> {
  if (ec_groups.size() not_eq postulate_random_points.size()) {
    std::unexpected(
        "ec_groups and postulate_random_points do not have the same size");
  }

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
  BN_CTX_unique_ptr bn_ctx{BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};

  OSSL_CHECK_OR_UNEXPECTED(BN_div(order_mean.get(), nullptr, order_mean.get(),
                                  order_length.get(), bn_ctx.get()),
                           "Bad execution of BN_div ");
  BN_unique_ptr nonce{BN_unique_ptr(BN_new(), ::BN_free)};
  OSSL_CHECK_OR_UNEXPECTED(BN_rand_range(nonce.get(), order_mean.get()),
                           "Bad execution of BN_rand_range ");

  for (auto const &[group, postulate_random_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points)) {
    EC_POINT_unique_ptr point{EC_POINT_new(group.get()), ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(group.get(), point.get(), nullptr,
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
    if (size <= 0) {
      return std::unexpected("Can not extract the buffer from point");
    }

    EVP_DigestUpdate(mdctx.get(), buf, size);
    OPENSSL_secure_clear_free(buf, size);

    size = EC_POINT_point2buf(group.get(), transient_point.get(),
                              POINT_CONVERSION_COMPRESSED, &buf, nullptr);
    if (size <= 0) {
      return std::unexpected("Can not extract the buffer from point");
    }

    EVP_DigestUpdate(mdctx.get(), buf, size);
    OPENSSL_secure_clear_free(buf, size);
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr);

  BN_unique_ptr challenge{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, challenge.get());
  return challenge;
}

auto solve_challenge(BN_unique_ptr const &secret, BN_unique_ptr const &nonce,
                     BN_unique_ptr const &challenge) -> BN_unique_ptr {
  BN_CTX_unique_ptr const bn_ctx{
      BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};
  BN_unique_ptr response{BN_unique_ptr(BN_new(), ::BN_free)};

  //  r = (v - (x * c))
  // r_response = (v_commitment - (x_secret * c_challenge))
  assert(BN_mul(response.get(), secret.get(), challenge.get(), bn_ctx.get()) ==
         1);
  assert(BN_sub(response.get(), nonce.get(), response.get()) == 1);
  // assert(BN_div(nullptr, r_response, r_response, order, ctx) == 1);
  // printBN("r ", r_response);
  return response;
}

auto verify(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
            std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
            std::vector<EC_POINT_unique_ptr> const &commitments,
            std::vector<EC_POINT_unique_ptr> const &transient_points,
            BN_unique_ptr const &challenge, BN_unique_ptr const &proof) {
  for (auto const &[ec_group, postulate_random_point, commitment,
                    transient_point] :
       std::ranges::views::zip(ec_groups, postulate_random_points, commitments,
                               transient_points)) {
    EC_POINT_unique_ptr point_step_one{EC_POINT_new(ec_group.get()),
                                       ::EC_POINT_free};
    assert(EC_POINT_mul(ec_group.get(), point_step_one.get(), nullptr,
                        postulate_random_point.get(), proof.get(),
                        nullptr) == 1);
    EC_POINT_unique_ptr point_step_two{EC_POINT_new(ec_group.get()),
                                       ::EC_POINT_free};
    assert(EC_POINT_mul(ec_group.get(), point_step_two.get(), nullptr,
                        commitment.get(), challenge.get(), nullptr) == 1);
    EC_POINT_unique_ptr point_step_three{EC_POINT_new(ec_group.get()),
                                         ::EC_POINT_free};
    assert(EC_POINT_add(ec_group.get(), point_step_three.get(),
                        point_step_one.get(), point_step_two.get(),
                        nullptr) == 1);
    if (EC_POINT_cmp(ec_group.get(), transient_point.get(),
                     point_step_three.get(), nullptr) not_eq 0) {
      std::println("Verification failed");
      printEC_POINT(ec_group.get(), "transient_point ", transient_point.get());
      printEC_POINT(ec_group.get(), "point_step_three ",
                    point_step_three.get());
      return false;
    }
  }
  std::println("Verification succeeded");

  return true;
}

//  Verify(groups,
//                       {c_challenge, r_response, vg_commitment,
//                       vh_commitment}, postulate_random_points, // v
//                       {xg_scalar, xh_scalar})

namespace otp {

// Helper function to convert the current time to a TOTP time step
constexpr uint64_t default_time_step{30UL};
inline auto getTimeStep(uint64_t time_step = default_time_step) -> uint64_t {
  return std::time(nullptr) / time_step;
}

template <Integral integer>
inline auto integer_to_bytes(integer const &value)
    -> std::array<std::byte, sizeof(integer)> {
  // Use std::bit_cast to reinterpret the integer as a std::byte array
  return std::bit_cast<std::array<std::byte, sizeof(integer)>>(value);
}

template <Integral integer>
inline void printBytes(std::span<const std::byte> const &bytes) {
  // Use ranges to create a hex string for bytes and use std::println
  for (auto const &byte : bytes | std::views::transform([](std::byte __b) {
                            return std::to_integer<integer>(__b);
                          })) {
    std::println("{:02x} ", byte);  // Print in hexadecimal format
  }
}

// auto
// generate_hmac(std::string_view const& hashing_algorithm_name)
//   -> std::expected<std::string const, std::string>
// {
//   char* data = nullptr;
//   uint64_t data_length{};
//   EVP_MD_CTX_unique_ptr const evp_md_ctx{ EVP_MD_CTX_new(), ::EVP_MD_CTX_free
//   }; OSSL_CHECK_NULL_OR_UNEXPECTED(
//     evp_md_ctx, "Cannot initialize message digests context : "sv)
//   EVP_MD_unique_ptr const evp_md{
//     EVP_MD_fetch(nullptr, hashing_algorithm_name.data(), nullptr),
//     ::EVP_MD_free
//   };
//   EVP_DigestInit_ex(evp_md_ctx.get(), evp_md.get(), nullptr);
//   EVP_DigestUpdate(evp_md_ctx.get(),
//                    hashing_algorithm_name.data(),
//                    hashing_algorithm_name.length());
//   EVP_DigestFinal_ex(evp_md_ctx, result, resultLength);
// }

} /* namespace otp  */

}  // namespace crypto

// Function to generate an HMAC-SHA1 hash using OpenSSL 3.0
unsigned char *generateHMAC(const unsigned char *data, int dataLength,
                            unsigned char *result, unsigned int *resultLength) {
  EVP_MD_CTX *evp_md_ctx = EVP_MD_CTX_new();
  EVP_MD *evp_md = EVP_MD_fetch(nullptr, "SHA1", nullptr);
  EVP_DigestInit_ex(evp_md_ctx, evp_md, nullptr);
  EVP_DigestUpdate(evp_md_ctx, data, dataLength);

  EVP_DigestFinal_ex(evp_md_ctx, result, resultLength);
  EVP_MD_CTX_free(evp_md_ctx);

  return result;
}

// Function to generate a TOTP code
std::string generateTOTP(const std::string &secretKey, int digits = 6,
                         int timeStep = crypto::otp::default_time_step) {
  // Convert the secret key to a byte array
  const unsigned char *key =
      reinterpret_cast<const unsigned char *>(secretKey.c_str());
  int keyLength = secretKey.length();

  // Get the current time step
  uint64_t currentTimeStep = crypto::otp::getTimeStep(timeStep);

  // Convert the time step to a byte array (8 bytes)
  auto data = crypto::otp::integer_to_bytes(currentTimeStep);

  // Generate the HMAC-SHA1 hash
  constexpr auto sha1_digest_length{20U};
  // std::array<uint8_t, sha1_digest_length> hash;
  unsigned char hmacResult[sha1_digest_length];
  unsigned int hmacLength = 0;
  generateHMAC((const unsigned char *)data.cbegin(), data.size(), hmacResult,
               &hmacLength);

  // Dynamic truncation to extract a 4-byte integer from the hash
  int offset =
      hmacResult[hmacLength - 1] & 0x0F;  // Use the last nibble as the offset
  uint32_t binaryCode = (hmacResult[offset] & 0x7F) << 24 |
                        (hmacResult[offset + 1] & 0xFF) << 16 |
                        (hmacResult[offset + 2] & 0xFF) << 8 |
                        (hmacResult[offset + 3] & 0xFF);

  // Compute the TOTP value by taking the modulo with 10^digits
  uint32_t otp = binaryCode % static_cast<uint32_t>(pow(10, digits));

  // Format the OTP with leading zeros if needed
  std::stringstream ss;
  ss << std::setw(digits) << std::setfill('0') << otp;
  return ss.str();
}

// https://eprint.iacr.org/2022/1593.pdf
// http://fc13.ifca.ai/proc/5-1.pdf

// Logarithm Equality (DLEQ) proof
// https://asecuritysite.com/encryption/go_dleq

// Helper function to print EC_POINT values in hexadecimal

auto generate_random_scalar(EC_GROUP const *group) -> BIGNUM * {
  BIGNUM *order = BN_new();
  BIGNUM *random_scalar = BN_new();
  EC_GROUP_get_order(group, order, nullptr);
  BN_rand_range(random_scalar, order);
  BN_free(order);
  return random_scalar;
}

auto generate_random_scalar(
    std::tuple<EC_GROUP const *, EC_GROUP const *> const groups) -> BIGNUM * {
  auto const &[group_g, group_H]{groups};
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *order_mean = BN_new();
  BIGNUM *order_g = BN_new();
  BIGNUM *order_h = BN_new();
  BIGNUM *order_length = BN_new();
  BIGNUM *random_scalar = BN_new();
  assert(BN_dec2bn(&order_length, "2") == 1);

  EC_GROUP_get_order(group_g, order_g, nullptr);
  EC_GROUP_get_order(group_H, order_h, nullptr);

  BN_add(order_mean, order_h, order_h);
  BN_add(order_mean, order_g, order_g);

  BN_div(order_mean, nullptr, order_mean, order_length, ctx);

  BN_rand_range(random_scalar, order_mean);
  BN_free(order_mean);
  BN_free(order_g);
  BN_free(order_h);

  return random_scalar;
}

auto generate_random_point(EC_GROUP const *group) -> EC_POINT * {
  BN_CTX *ctx = BN_CTX_new();
  const EC_POINT *generator = EC_GROUP_get0_generator(group);
  EC_POINT *point = EC_POINT_dup(generator, group);
  BIGNUM *random_scalar = generate_random_scalar(group);
  BIGNUM const *order = EC_GROUP_get0_order(group);
  printBN("Big random_scalar ", random_scalar);
  assert(BN_div(nullptr, random_scalar, random_scalar, order, ctx) == 1);
  printBN("Big random_scalar ", random_scalar);
  assert(EC_POINT_mul(group, point, nullptr, point, random_scalar, nullptr) ==
         1);
  return point;
}

// Commitment Registration
auto generate_challenge_commitment(
    std::tuple<EC_GROUP const *, EC_GROUP const *> const groups,
    std::tuple<EC_POINT const *, EC_POINT const *> const
        postulate_random_points,
    BIGNUM const *x_secret) -> std::tuple<EC_POINT *, EC_POINT *> {
  auto const &[group_g, group_H]{groups};

  const auto &[postulate_point_g, postulate_point_h] = postulate_random_points;
  // BIGNUM const* order_g = EC_GROUP_get0_order(group_g);
  // BIGNUM const* order_h = EC_GROUP_get0_order(group_H);
  // printBN("order ", order);

  // =======
  // xG = x * G;
  EC_POINT *xG = EC_POINT_new(group_g);
  printEC_POINT(group_g, "G ", postulate_point_g);
  assert(EC_POINT_mul(group_g, xG, nullptr, postulate_point_g, x_secret,
                      nullptr) == 1);
  printEC_POINT(group_g, "xG ", xG);

  // xH = x * H;
  EC_POINT *xH = EC_POINT_new(group_H);
  printEC_POINT(group_H, "H ", postulate_point_h);
  assert(EC_POINT_mul(group_H, xH, nullptr, postulate_point_h, x_secret,
                      nullptr) == 1);
  printEC_POINT(group_H, "xH ", xH);

  return {xG, xH};
}

auto generate_chalenge_from_commitment(
    std::tuple<EC_GROUP const *, EC_GROUP const *> const groups,
    std::tuple<EC_POINT const *, EC_POINT const *> const
        postulate_random_points)
    -> std::tuple<BIGNUM *, EC_POINT *, EC_POINT *> {
  auto const &[group_g, group_H]{groups};

  auto const &[G, H] = postulate_random_points;

  BIGNUM *v_commitment = generate_random_scalar(groups);
  printBN("v_commitment ", v_commitment);

  // vG = v * G
  EC_POINT *vg_point = EC_POINT_new(group_g);
  assert(EC_POINT_mul(group_g, vg_point, nullptr, G, v_commitment, nullptr) ==
         1);
  printEC_POINT(group_g, "vG ", vg_point);

  // vH = v * H
  EC_POINT *vh_point = EC_POINT_new(group_H);
  assert(EC_POINT_mul(group_H, vh_point, nullptr, H, v_commitment, nullptr) ==
         1);
  printEC_POINT(group_H, "vH ", vh_point);

  return {v_commitment, vg_point, vh_point};
}

auto generate_challenge(
    std::tuple<EC_GROUP const *, EC_GROUP const *> const groups,
    EC_POINT const *xG, EC_POINT const *xH, EC_POINT const *vG,
    EC_POINT const *vH) -> BIGNUM * {
  auto const &[group_g, group_H]{groups};
  // BN_CTX* ctx = BN_CTX_new();
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  EVP_MD *evp_md = EVP_MD_fetch(nullptr, "SHA256", nullptr);
  EVP_DigestInit_ex(mdctx, evp_md, nullptr);

  // BIGNUM const* order = EC_GROUP_get0_order(group);
  // BIGNUM const* order = EC_GROUP_get0_order(group);

  BIGNUM *c_challenge = BN_new();

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;

  uint8_t *buf;
  assert(EC_POINT_point2buf(group_g, xG, POINT_CONVERSION_COMPRESSED, &buf,
                            nullptr) > 0);
  EVP_DigestUpdate(mdctx, buf, strlen((char *)buf));
  OPENSSL_free(buf);

  assert(EC_POINT_point2buf(group_H, xH, POINT_CONVERSION_COMPRESSED, &buf,
                            nullptr) > 0);
  EVP_DigestUpdate(mdctx, buf, strlen((char *)buf));
  free(buf);

  assert(EC_POINT_point2buf(group_g, vG, POINT_CONVERSION_COMPRESSED, &buf,
                            nullptr) > 0);
  EVP_DigestUpdate(mdctx, buf, strlen((char *)buf));
  free(buf);

  assert(EC_POINT_point2buf(group_H, vH, POINT_CONVERSION_COMPRESSED, &buf,
                            nullptr) > 0);
  EVP_DigestUpdate(mdctx, buf, strlen((char *)buf));
  free(buf);

  EVP_DigestFinal_ex(mdctx, hash.data(), nullptr);
  EVP_MD_CTX_free(mdctx);

  BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, c_challenge);

  printBN("c ", c_challenge);

  return c_challenge;
}

auto solve_challenge(BIGNUM const *x_secret, BIGNUM const *c_challenge,
                     BIGNUM const *v_commitment) -> BIGNUM * {
  BN_CTX *ctx = BN_CTX_new();
  // BIGNUM const* order = EC_GROUP_get0_order(group);
  BIGNUM *r_response = BN_new();

  //  r = (v - (x * c))
  // r_response = (v_commitment - (x_secret * c_challenge))
  assert(BN_mul(r_response, x_secret, c_challenge, ctx) == 1);
  printBN("r ", r_response);
  printBN("v ", v_commitment);

  assert(BN_sub(r_response, v_commitment, r_response) == 1);
  printBN("r ", r_response);
  // assert(BN_div(nullptr, r_response, r_response, order, ctx) == 1);
  // printBN("r ", r_response);
  return r_response;
}

// use a traditional Weierstrass elliptic curve
// g++ -std=c++23 -g LE.cpp -lcrypto -lssl && ./a.out

auto Verify(std::tuple<EC_GROUP const *, EC_GROUP const *> const groups,
            std::tuple<BIGNUM const *, BIGNUM const *, EC_POINT *,
                       EC_POINT *> const proof,
            std::tuple<EC_POINT const *, EC_POINT const *> const
                postulate_random_points,
            std::tuple<EC_POINT const *, EC_POINT const *> const commitment) {
  auto const &[group_g, group_H]{groups};

  auto const &[g_point, h_point] = postulate_random_points;

  auto const &[c, r, vg_point, vh_point] = proof;

  auto const &[xG, xH] = commitment;

  // rG = r * G
  EC_POINT *const rg_point = EC_POINT_new(group_g);
  assert(EC_POINT_mul(group_g, rg_point, nullptr, g_point, r, nullptr) == 1);
  printEC_POINT(group_g, "rG ", rg_point);
  // cxG = c * xG
  EC_POINT *const cxg_point = EC_POINT_new(group_g);
  assert(EC_POINT_mul(group_g, cxg_point, nullptr, xG, c, nullptr) == 1);
  printEC_POINT(group_g, "cxG ", cxg_point);
  // a = rG + cxG
  EC_POINT *const a = EC_POINT_new(group_g);
  assert(EC_POINT_add(group_g, a, rg_point, cxg_point, nullptr) == 1);
  printEC_POINT(group_g, "a  ", a);

  // rH = r * H
  EC_POINT *const rh_point = EC_POINT_new(group_H);
  assert(EC_POINT_mul(group_H, rh_point, nullptr, h_point, r, nullptr) == 1);
  printEC_POINT(group_H, "rH ", rh_point);
  // cxH = c * xH
  EC_POINT *const cxh_point = EC_POINT_new(group_H);
  assert(EC_POINT_mul(group_H, cxh_point, nullptr, xH, c, nullptr) == 1);
  printEC_POINT(group_H, "cxH ", cxh_point);
  // b = rH + cxH
  EC_POINT *const b = EC_POINT_new(group_H);
  assert(EC_POINT_add(group_H, b, rh_point, cxh_point, nullptr) == 1);
  printEC_POINT(group_H, "b ", b);

  printEC_POINT(group_g, "vG ", vg_point);
  printEC_POINT(group_g, "a ", a);
  printEC_POINT(group_H, "vH ", vh_point);
  printEC_POINT(group_H, "b ", b);
  std::cout << EC_POINT_cmp(group_g, vg_point, a, nullptr) << std::endl;
  std::cout << EC_POINT_cmp(group_H, vh_point, b, nullptr) << std::endl;

  bool success = ((EC_POINT_cmp(group_g, vg_point, a, nullptr) == 0) &&
                  (EC_POINT_cmp(group_H, vh_point, b, nullptr) == 0));

  if (success) {
    std::cout << "Alice has proven to bob she know the password" << std::endl;
  } else {
    std::cout << "Verification failed!" << std::endl;
  }
  return success;
}

#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/reflection.h"
#include "flatbuffers/util.h"

// g++ -fno-elide-constructors -std=c++23 -g LE.cpp
// /usr/local/lib/libflatbuffers.a -lcrypto -lssl && ./a.out
//
//  openssl ecparam
// -list_curves

// https://sebastiaagramunt.medium.com/discrete-logarithm-problem-and-diffie-hellman-key-exchange-821a45202d26

// https://www.getmonero.org/resources/research-lab/pubs/MRL-0010.pdf
// https://eprint.iacr.org/2022/1593.pdf

// https://datatracker.ietf.org/doc/draft-hao-schnorr/05/
// https://www.rfc-editor.org/rfc/pdfrfc/rfc8235.txt.pdf
// https://asecuritysite.com/zero/dleq_z

// https://github.com/sdiehl/schnorr-nizk
// https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf
auto main(int argc, const char **argv) -> int {
  flatbuffers::FlatBufferBuilder builder(1024);

  {
    // Sample data
    // Statement
    //  openssl ecparam -list_curves
    std::vector<std::string> curve_names = {
        "secp256k1", "prime256v1", "wap-wsg-idm-ecid-wtls6", "c2pnb304w1"};
    std::vector<std::string> postulate_coordinates = {"p_coord1", "p_coord2",
                                                      "p_coord2"};
    std::vector<std::string> commitment_coordinates = {"c_coord1", "c_coord2",
                                                       "p_coord2"};

    auto sigma = /* NIDLEQ:: */ CreateSigma(
        builder, builder.CreateVectorOfStrings(curve_names),
        builder.CreateVectorOfStrings(postulate_coordinates),
        builder.CreateVectorOfStrings(commitment_coordinates));
    builder.Finish(sigma);  // ✅ sets root
    // Build the Sigma table
    // /* NIDLEQ:: */SigmaBuilder sigma_builder(builder);
    // sigma_builder.add_curve_name(curve_names_offset);
    // sigma_builder.add_postulate_coordinate(postulate_coordinates_offset);
    // sigma_builder.add_commitment_coordinate(commitment_coordinates_offset);
    // auto sigma_offset = sigma_builder.Finish();
    // builder.Finish(sigma_offset);
    const uint8_t *buffer = builder.GetBufferPointer();
    size_t size = builder.GetSize();

    // Load the schema file
    std::string schemafile;
    
    if (!flatbuffers::LoadFile("flatb/commitment.fbs", false, &schemafile)) {
      std::cerr << "Failed to load schema file" << std::endl;
      return 1;
    }
    flatbuffers::Parser parser;
    parser.opts.indent_step = 2;  // pretty JSON

    if (!parser.Parse(schemafile.c_str())) {
      std::cerr << "Schema parse failed" << std::endl;
      return 1;
    }

    flatbuffers::Verifier verifier(buffer, size);
    if (!/* NIDLEQ:: */ VerifySigmaBuffer(verifier)) {
      std::cerr << "Buffer verification failed" << std::endl;
      return 1;
    }

    if (!parser.root_struct_def_) {
      std::cerr << "No root type defined in schema" << std::endl;
      return 1;
    }
    std::cout << "Root type: " << parser.root_struct_def_->name << std::endl;

    std::string json;
    auto err = flatbuffers::GenerateText(parser, buffer, &json);
    if (err) {
      std::cerr << "Failed to generate JSON " << err << std::endl;
      return 1;
    }
    // std::println("json_output {}", json);

    auto get_ec_group_by_curves_name_expected =
        crypto::get_ec_group_by_curves_name(curve_names);

    if (not get_ec_group_by_curves_name_expected.has_value()) {
      std::println("get_ec_group_by_curves_name_expected error {}",
                   get_ec_group_by_curves_name_expected.error());
      exit(1);
    }

    auto &&ec_groups = std::move(get_ec_group_by_curves_name_expected.value());
    auto &&postulate_random_points_expected =
        crypto::generate_random_points_from(ec_groups);
    std::println("get_ec_group_by_curves_name_expected {}", ec_groups.size());

    if (not postulate_random_points_expected.has_value()) {
      std::println("postulate_nonce_points_expected error {}",
                   postulate_random_points_expected.error());
      exit(1);
    }

    auto const &&postulate_random_points =
        std::move(postulate_random_points_expected.value());
    std::println("postulate_nonce_points {}", postulate_random_points.size());

    auto const &&secret = crypto::hash_to_BIGNUM({"password"});
    printBN("secret =  ", secret.get());

    auto &&commitment_expected =
        crypto::generate_commitment(ec_groups, postulate_random_points, secret);

    if (not commitment_expected.has_value()) {
      std::println("commitments_expected error {}",
                   commitment_expected.error());
      exit(1);
    }

    auto const &&commitments = std::move(commitment_expected.value());
    std::println("commitments {}", commitments.size());

    // The Prover send to the verifer the postulate and the commitments (in
    // enrolement process) The Verifier generate the transient chalenge and send
    // it to the prover

    // Alice ask bob to prove that she knows the password, so bob generate the
    // transient chalenge (transient_points) based on the
    // postulate_random_points placed on ther respective eliptic curve group and
    // send the transient nonce to Alice
    auto &&transient_chalenge_expected =
        crypto::generate_transient_chalenge(ec_groups, postulate_random_points);

    if (not transient_chalenge_expected.has_value()) {
      std::println("transient_chalenge_expected error {}",
                   transient_chalenge_expected.error());
      exit(1);
    }
    auto const &&transient_chalenge =
        std::move(transient_chalenge_expected.value());
    auto &&[nonce, transient_points] = transient_chalenge;
    std::println("transient_chalenge {}", transient_points.size());

    auto challenge_expected =
        crypto::generate_challenge(ec_groups, commitments, transient_points);

    if (not challenge_expected.has_value()) {
      std::println("challenge_expected error {}", challenge_expected.error());
      exit(1);
    }

    // Bob also send the challenge generated from the commitment and the
    // transient nonce to Alice
    auto const &&challenge = std::move(challenge_expected.value());
    std::println("commitments {}", commitments.size());
    printBN("challenge ", challenge.get());

    auto const &&response = crypto::solve_challenge(secret, nonce, challenge);
    printBN("response ", response.get());

    if (crypto::verify(ec_groups, postulate_random_points, commitments,
                       transient_points, challenge, response)) {
      std::println("Alice proved to Bob she knows the password");
    } else {
      std::println("Verification failed");
    }
  }
  exit(0);
  // Example data
  std::vector<std::pair<std::string, std::string>> data = {
      {"curve1", "coordinate1"},
      {"curve2", "coordinate2"},
      {"curve3", "coordinate3"}};

  // std::vector<flatbuffers::Offset</* NIDLEQ:: */Point>> points_vec;
  // for (const auto &item : data) {
  //   auto curve_offset = builder.CreateString(item.first);
  //   auto coordinate_offset = builder.CreateString(item.second);

  //   /* NIDLEQ:: */PointBuilder point_builder(builder);
  //   point_builder.add_curve(curve_offset);
  //   point_builder.add_coordinate(coordinate_offset);
  //   auto point_offset = point_builder.Finish();

  //   points_vec.push_back(point_offset);
  // }

  // flatbuffers::Offset<
  // flatbuffers::Vector<flatbuffers::Offset</* NIDLEQ:: */Point>>>
  // coordinates{builder.};
  // builder.Finish(/* NIDLEQ:: */CreatePostulate(builder,coordinates));
  // Example usage
  std::string secretKey =
      "12345678901234567890";  // Replace with your base32 secret key
  int digits = 6;              // Number of digits in the OTP
  int timeStep = 30;           // Time step in seconds
  std::string totp = generateTOTP(secretKey, digits, timeStep);
  std::cout << "TOTP: " << totp << std::endl;

  // exit(1);
  std::tuple<EC_GROUP const *, EC_GROUP const *> const groups{
      EC_GROUP_new_by_curve_name(OBJ_sn2nid("secp256k1")),
      EC_GROUP_new_by_curve_name(OBJ_sn2nid("prime256v1")),
      // EC_GROUP_new_by_curve_name(OBJ_sn2nid("prime239v1")),

  };

  auto const &[group_g, group_h]{groups};

  // ========= Client ==========
  //
  // Generate random G and H and store it.
  // Postulate
  std::tuple<EC_POINT const *, EC_POINT const *> const postulate_random_points{
      generate_random_point(group_g), generate_random_point(group_h)};

  // auto const& [postulate_point_g, postulate_point_h]{
  // postulate_random_points
  // };

  crypto::BN_unique_ptr const x_registered_secret =
      crypto::hash_to_BIGNUM({"thesecret", "Data", totp});

  // Generate xG and xH with the ephemeral x_secret (TOTP) and store xG, xH
  // but not x_secret Commitment
  auto const &[xg_scalar, xh_scalar]{generate_challenge_commitment(
      groups, postulate_random_points, x_registered_secret.get())};

  // Send Postulate and Commitment to the server

  // ===================

  // Generate v_commitment, vG, and vH for each proof verification, and store
  // it for the time being
  auto const &[v_commitment, vg_commitment, vh_commitment]{
      generate_chalenge_from_commitment(groups, postulate_random_points)};

  // challenge = H(xG, xH, vG, vH)
  //===================
  BIGNUM const *c_challenge = generate_challenge(groups, xg_scalar, xh_scalar,
                                                 vg_commitment, vh_commitment);

  //  Send c_challenge and the v_commitment
  // ===================

  crypto::BN_unique_ptr const x_input_secret =
      crypto::hash_to_BIGNUM({"thesecret", "Data", totp});

  // load c_challenge, v_commitment from db and send it to the user

  // EC_POINT_point2hex();
  // EC_POINT_hex2point();
  // Response
  // r = (v - (x * c))
  BIGNUM const *r_response{
      solve_challenge(x_input_secret.get(), c_challenge, v_commitment)};
  // printBN("r_response ", r_response);

  // r_response is the response to the challenge

  std::cout << std::boolalpha
            << Verify(groups,
                      {c_challenge, r_response, vg_commitment, vh_commitment},
                      postulate_random_points,  // v
                      {xg_scalar, xh_scalar})
            << std::endl;

  return 0;
}

// flatc --cpp --gen-object-api --reflect-types --reflect-names
// --gen-json-emit
// --gen-mutable -I . -o datastructure commitment.fbs

// A.0
// Client define curve group parameter
// ex, G1=prime256v1, G2=prime256v1 ... Gn
// - Store the curves group parameter GP in DB
// On theses curve generate N random points
// - Store the curves point group parameter GP in DB
// - And send it to the server
// =========
// Client hash his password to create a big number
// - client initialize_challenge_commitment from the curves group parameter,
// postulate_random_points received and the x_registered_secret computed from
// secret
// And send the server the v_commitment, Vg commitment for curves group
// parameter the serve store the commitment for later create chanlenge so the
// client can prove he still know
