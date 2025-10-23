#include <sys/types.h>

#include <expected>
#include <format>
#include <ranges>

#include <flatbuffers/flatbuffer_builder.h>
#include <flatbuffers/flatbuffers.h>
#include <flatbuffers/idl.h>
#include <flatbuffers/reflection.h>
#include <flatbuffers/util.h>
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

#include <array>
#include <flatbuffer/proving_phase_generated.h>
#include <flatbuffer/setup_phase_generated.h>
#include <flatbuffer/transient_generated.h>
#include <ios>
#include <span>
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
  auto &&result_name = (expression);                                   \
  if (not(result_name.has_value())) [[likely]] {                       \
    return std::unexpected(std::format("{} : {}", result_name.error(), \
                                       ERR_error_string(0, nullptr))); \
  }                                                                    \
  definition = std::move(result_name.value());
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
    auto const curve_nid = OBJ_sn2nid(curve_name.c_str());
    if (curve_nid == NID_undef) {
      return std::unexpected(
          std::format("Can not find the nid of ({})", curve_name));
    }
    EC_GROUP_unique_ptr ec_group_unique_ptr{
        EC_GROUP_new_by_curve_name(curve_nid), ::EC_GROUP_free};
    OSSL_CHECK_NULL_OR_UNEXPECTED(
        ec_group_unique_ptr,
        std::format("Can not create group for the nid : ({}) : ", curve_nid));
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

auto EC_POINT_to_hex(std::tuple<EC_GROUP_unique_ptr const &,
                                EC_POINT_unique_ptr const &> &&group_point)
    -> std::expected<std::string, std::string> {
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

auto EC_POINTS_to_hex(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
                      std::vector<EC_POINT_unique_ptr> const &ec_points)
    -> std::expected<std::vector<std::string>, std::string> {
  if (ec_groups.size() not_eq ec_points.size()) {
    std::unexpected("ec_groups and ec_points do not have the same size");
  }
  std::vector<std::string> point_hex;
  point_hex.reserve(ec_groups.size());

  for (auto const &[group, point] :
       std::ranges::views::zip(ec_groups, ec_points)) {
    ASSIGN_OR_UNEXPECTED(auto &&ec_point_to_hex,
                         EC_POINT_to_hex(std::forward_as_tuple(group, point)))
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

auto generate_transient_challenge(
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
  BN_CTX_unique_ptr const bn_ctx{
      BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};

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
      return false;
    }
  }
  std::println("Verification succeeded");

  return true;
}

}  // namespace crypto

template <typename VerifierType>
auto debug_print_flatbuffer(std::span<const uint8_t> const &buffer,
                            std::string const &schema_file,
                            std::vector<std::string> const &include_dir = {}) {
  // Load the schema file
  std::string schemafile;

  std::vector<const char *> include_pointers;
  include_pointers.reserve(include_dir.size());
  for (const auto &str : include_dir) {
    include_pointers.push_back(str.c_str());
  }
  const char **paths_for_func = include_pointers.data();

  if (!flatbuffers::LoadFile(schema_file.c_str(), false, &schemafile)) {
    std::println("Failed to load schema file {}", schema_file);
    return;
  }
  flatbuffers::Parser parser;
  parser.opts.indent_step = 2;  // pretty JSON

  if (!parser.Parse(schemafile.c_str(), paths_for_func)) {
    std::println("Schema parse failed: -- {}", schemafile);
    return;
  }

  flatbuffers::Verifier verifier(buffer.data(), buffer.size());

  if constexpr (std::same_as<VerifierType, zerauth::Setup>) {
    if (!zerauth::VerifySetupBuffer(verifier)) {
      std::println("VerifySetupBuffer verification failed");
      return;
    }
  } else if (std::same_as<VerifierType, zerauth::Proving>) {
    if (!zerauth::VerifyProvingBuffer(verifier)) {
      std::println("VerifyProvingBuffer verification failed");
      return;
    }
  } else if (std::same_as<VerifierType, zerauth::Transient>) {
    if (!zerauth::VerifyTransientBuffer(verifier)) {
      std::println("VerifyTransientBuffer verification failed");
      return;
    }
  } else {
    std::println("Buffer verification failed");
    return;
  }

  if (parser.root_struct_def_ == nullptr) {
    std::println("No root type defined in schema");
    return;
  }

  std::println("Root type: {}", parser.root_struct_def_->name);

  std::string json;
  auto const *const err =
      flatbuffers::GenerateText(parser, buffer.data(), &json);

  if (err not_eq nullptr) {
    std::println("Failed to generate JSON {}", err);
    return;
  }
  std::println("json gen : {}", json);
}

// g++ -fno-elide-constructors -std=c++23 -g LE.cpp
// /usr/local/lib/libflatbuffers.a -lcrypto -lssl && ./a.out
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
auto main(int argc, const char **argv) -> int {
  // Sample data
  // Statement
  //  openssl ecparam -list_curves
  std::vector<std::string> curve_names = {
      "secp256k1", "prime256v1", "wap-wsg-idm-ecid-wtls6", "c2pnb304w1"};

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
    std::println("commitments_expected error {}", commitment_expected.error());
    exit(1);
  }

  auto const &&commitments = std::move(commitment_expected.value());
  std::println("commitments {}", commitments.size());
  auto &&postulate_random_points_hex =
      crypto::EC_POINTS_to_hex(ec_groups, postulate_random_points);

  auto &&commitments_points_hex =
      crypto::EC_POINTS_to_hex(ec_groups, commitments);

  {
    flatbuffers::FlatBufferBuilder builder;
    auto setup_buffer = zerauth::CreateSetup(
        builder, builder.CreateVectorOfStrings(curve_names),
        builder.CreateVectorOfStrings(postulate_random_points_hex.value()),
        builder.CreateVectorOfStrings(commitments_points_hex.value()));
    // Build the Setup table
    builder.Finish(setup_buffer);  // ✅ sets root
                                   // zerauth::VerifySetupBuffer
    debug_print_flatbuffer<zerauth::Setup>(
        {builder.GetBufferPointer(), builder.GetSize()},
        "flatb/setup_phase.fbs", {"flatb/"});
  }

  // The Prover send to the verifer the postulate and the commitments (in
  // enrolement process) The Verifier generate the transient challenge and
  // send it to the prover

  // Alice ask bob to prove that she knows the password, so bob generate the
  // transient challenge (transient_points) based on the
  // postulate_random_points placed on ther respective eliptic curve group and
  // send the transient nonce to Alice
  auto &&transient_challenge_expected =
      crypto::generate_transient_challenge(ec_groups, postulate_random_points);

  if (not transient_challenge_expected.has_value()) {
    std::println("transient_challenge_expected error {}",
                 transient_challenge_expected.error());
    exit(1);
  }
  auto const &&transient_challenge =
      std::move(transient_challenge_expected.value());
  auto &&[nonce, transient_points] = transient_challenge;
  std::println("transient_challenge {}", transient_points.size());

  auto challenge_expected =
      crypto::generate_challenge(ec_groups, commitments, transient_points);

  if (not challenge_expected.has_value()) {
    std::println("challenge_expected error {}", challenge_expected.error());
    exit(1);
  }
  // Bob also send the challenge generated from the commitment and the
  // transient nonce to Alice
  auto const &&challenge = std::move(challenge_expected.value());
  {
    auto &&nonce_hex = crypto::BIGNUM_to_hex(nonce);
    auto &&challenge_hex = crypto::BIGNUM_to_hex(challenge);

    {
      flatbuffers::FlatBufferBuilder builder;
      auto setup_proving = zerauth::CreateProving(
          builder, builder.CreateString(nonce_hex.value().c_str()),
          builder.CreateString(challenge_hex.value().c_str()));
      // Build the Sigma table
      builder.Finish(setup_proving);  // ✅ sets root
      debug_print_flatbuffer<zerauth::Proving>(
          {builder.GetBufferPointer(), builder.GetSize()},
          "flatb/proving_phase.fbs", {"flatb/"});
    }

    {
      flatbuffers::FlatBufferBuilder builder;
      auto &&nonce_hex = crypto::BIGNUM_to_hex(nonce);
      auto &&transient_challenge_hex =
          crypto::EC_POINTS_to_hex(ec_groups, transient_points);

      auto setup_transient = zerauth::CreateTransient(
          builder,

          zerauth::CreateSetup(
              builder, builder.CreateVectorOfStrings(curve_names),
              builder.CreateVectorOfStrings(
                  postulate_random_points_hex.value()),
              builder.CreateVectorOfStrings(commitments_points_hex.value())),
          zerauth::CreateProving(
              builder, builder.CreateString(nonce_hex.value().c_str()),
              builder.CreateString(challenge_hex.value().c_str())),
          builder.CreateVectorOfStrings(transient_challenge_hex.value()));
      // Build the Sigma table
      builder.Finish(setup_transient);  // ✅ sets root
      debug_print_flatbuffer<zerauth::Transient>(
          {builder.GetBufferPointer(), builder.GetSize()},
          "flatb/transient.fbs", {"flatb/"});
    }
  }

  // Alice execute and return the response
  // Proving : nonce, challenge
  auto const &&response = crypto::solve_challenge(secret, nonce, challenge);
  printBN("response ", response.get());

  // H(nonce, challenge) : Transient =   + Setup{curve_names,
  // postulate_coordinates, commitment_coordinates} +
  if (crypto::verify(ec_groups, postulate_random_points, commitments,
                     transient_points, challenge, response)) {
    std::println("Alice proved to Bob she knows the password");
  } else {
    std::println("Verification failed");
  }

  return 0;
}
