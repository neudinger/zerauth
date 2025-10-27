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

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <array>
#include <flatbuffer/proving_phase_generated.h>
#include <flatbuffer/setup_phase_generated.h>
#include <flatbuffer/transient_generated.h>
#include <span>
#include <type_traits>

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
#define OSSL_ASSIGN_OR_UNEXPECTED_IMPL(result_name, definition, expression) \
  auto &&result_name = (expression);                                        \
  if (not(result_name.has_value())) [[likely]] {                            \
    return std::unexpected(std::format("{} : {}", result_name.error(),      \
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
using OSSL_LIB_CTX_ptr =
    typename std::unique_ptr<OSSL_LIB_CTX, decltype(&::OSSL_LIB_CTX_free)>;

inline auto crypto_char_free(void *const ptr) -> void { OPENSSL_free(ptr); }
using CRYPTO_char_unique_ptr =
    typename std::unique_ptr<char, decltype(&crypto::crypto_char_free)>;

template <class T>
concept Integral = std::is_integral_v<T>;
template <typename TYPE>
concept StringLike = std::is_convertible_v<TYPE, std::string>;

auto get_ec_group_by_curves_name(std::vector<std::string> const &curves_name)
    -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string> {
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

auto hex_to_BIGNUM(std::string const &hex_big_num)
    -> std::expected<BN_unique_ptr const, std::string> {
  BN_unique_ptr big_number{BN_unique_ptr(BN_new(), ::BN_free)};

  BIGNUM *ptr = big_number.get();
  OSSL_CHECK_OR_UNEXPECTED(BN_hex2bn(&ptr, hex_big_num.c_str()),
                           "Cannot convert hexa string to BIG NUMBER");

  return big_number;
}

auto BIGNUM_to_hex(BN_unique_ptr const &bignumber)
    -> std::expected<std::string const, std::string> {
  CRYPTO_char_unique_ptr const num_hex_str{BN_bn2hex(bignumber.get()),
                                           crypto::crypto_char_free};
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
  OSSL_CHECK_NULL_OR_UNEXPECTED(point_position_hex_str,
                                "Cannot convert EC_POINT to hexa string : "sv)

  return std::string{point_position_hex_str.get(),
                     std::strlen(point_position_hex_str.get())};
}

auto hex_to_EC_POINT(
    std::tuple<EC_GROUP_unique_ptr const &, std::string const &> &&group_point)
    -> std::expected<EC_POINT_unique_ptr, std::string> {
  auto const &[group, point_hex]{group_point};
  EC_POINT_unique_ptr point_ec{EC_POINT_new(group.get()), ::EC_POINT_free};

  OSSL_CHECK_NULL_OR_UNEXPECTED(
      EC_POINT_hex2point(group.get(), point_hex.c_str(), point_ec.get(),
                         nullptr),
      "Cannot convert hexa string to EC_POINT ");

  return point_ec;
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
    OSSL_ASSIGN_OR_UNEXPECTED(
        auto &&ec_point_to_hex,
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
  BN_unique_ptr hash_number{BN_unique_ptr(
      BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, nullptr), ::BN_free)};
  OSSL_CHECK_NULL_OR_UNEXPECTED(mdctx, "hash_to_BIGNUM BN_bin2bn fail ")
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

    OSSL_CHECK_OR_UNEXPECTED(EVP_DigestUpdate(mdctx.get(), buf, size),
                             "ERROR: EVP_DigestUpdate");
    OPENSSL_secure_clear_free(buf, size);

    size = EC_POINT_point2buf(group.get(), transient_point.get(),
                              POINT_CONVERSION_COMPRESSED, &buf, nullptr);
    if (size <= 0) {
      return std::unexpected("Can not extract the buffer from point");
    }

    OSSL_CHECK_OR_UNEXPECTED(EVP_DigestUpdate(mdctx.get(), buf, size),
                             "ERROR: EVP_DigestUpdate");
    OPENSSL_secure_clear_free(buf, size);
  }

  std::array<uint8_t, SHA256_DIGEST_LENGTH> hash;
  OSSL_CHECK_OR_UNEXPECTED(
      EVP_DigestFinal_ex(mdctx.get(), hash.data(), nullptr),
      "ERROR: EVP_DigestFinal_ex");

  BN_unique_ptr challenge{BN_unique_ptr(BN_new(), ::BN_free)};
  BN_bin2bn(hash.data(), SHA256_DIGEST_LENGTH, challenge.get());
  return challenge;
}

auto solve_challenge(BN_unique_ptr const &secret, BN_unique_ptr const &nonce,
                     BN_unique_ptr const &challenge)
    -> std::expected<BN_unique_ptr, std::string> {
  BN_CTX_unique_ptr const bn_ctx{
      BN_CTX_unique_ptr(BN_CTX_new(), ::BN_CTX_free)};
  BN_unique_ptr response{BN_unique_ptr(BN_new(), ::BN_free)};

  //  r = (v - (x * c))
  // r_response = (v_commitment - (x_secret * c_challenge))
  OSSL_CHECK_OR_UNEXPECTED(
      BN_mul(response.get(), secret.get(), challenge.get(), bn_ctx.get()),
      "solve_challenge BN_mul error ");
  OSSL_CHECK_OR_UNEXPECTED(BN_sub(response.get(), nonce.get(), response.get()),
                           "solve_challenge BN_sub error ");
  return response;
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
        "verify EC_POINT_mul error ");
    EC_POINT_unique_ptr point_step_two{EC_POINT_new(ec_group.get()),
                                       ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_mul(ec_group.get(), point_step_two.get(), nullptr,
                     commitment.get(), challenge.get(), nullptr),
        "verify EC_POINT_mul error ");
    EC_POINT_unique_ptr point_step_three{EC_POINT_new(ec_group.get()),
                                         ::EC_POINT_free};
    OSSL_CHECK_OR_UNEXPECTED(
        EC_POINT_add(ec_group.get(), point_step_three.get(),
                     point_step_one.get(), point_step_two.get(), nullptr),
        "verify EC_POINT_add error ");

    switch (EC_POINT_cmp(ec_group.get(), transient_point.get(),
                         point_step_three.get(), nullptr)) {
      case -1: {
        return std::unexpected("verify EC_POINT_cmp error ");
      }
      case 0: {
        return false;
      }
      default:
        break;
    }
  }
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

  ASSIGN_OR_EXIT(auto const ec_groups,
                 crypto::get_ec_group_by_curves_name(curve_names));

  ASSIGN_OR_EXIT(auto const postulate_random_points,
                 crypto::generate_random_points_from(ec_groups));

  ASSIGN_OR_EXIT(auto const secret, crypto::hash_to_BIGNUM({"password"}));

  ASSIGN_OR_EXIT(
      auto const commitments,
      crypto::generate_commitment(ec_groups, postulate_random_points, secret))

  std::println("commitments {}", commitments.size());

  ASSIGN_OR_EXIT(auto const postulate_random_points_hex,
                 crypto::EC_POINTS_to_hex(ec_groups, postulate_random_points))

  ASSIGN_OR_EXIT(auto const commitments_points_hex,
                 crypto::EC_POINTS_to_hex(ec_groups, commitments))

  {
    flatbuffers::FlatBufferBuilder builder;
    // Build the Setup table
    builder.Finish(zerauth::CreateSetup(
        builder, builder.CreateVectorOfStrings(curve_names),
        builder.CreateVectorOfStrings(postulate_random_points_hex),
        builder.CreateVectorOfStrings(commitments_points_hex)));
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

  ASSIGN_OR_EXIT(
      auto const transient_challenge,
      crypto::generate_transient_challenge(ec_groups, postulate_random_points))
  auto &&[nonce, transient_points] = transient_challenge;
  std::println("transient_challenge {}", transient_points.size());

  // Bob also send the challenge generated from the commitment and the
  // transient nonce to Alice
  ASSIGN_OR_EXIT(
      auto const challenge,
      crypto::generate_challenge(ec_groups, commitments, transient_points))

  {
    ASSIGN_OR_EXIT(auto const nonce_hex, crypto::BIGNUM_to_hex(nonce))
    ASSIGN_OR_EXIT(auto const challenge_hex, crypto::BIGNUM_to_hex(challenge))

    flatbuffers::FlatBufferBuilder builder_proving;
    auto proving_offset = zerauth::CreateProving(
        builder_proving, builder_proving.CreateString(nonce_hex.c_str()),
        builder_proving.CreateString(challenge_hex.c_str()));
    // Build the Sigma table
    builder_proving.Finish(proving_offset);
    debug_print_flatbuffer<zerauth::Proving>(
        {builder_proving.GetBufferPointer(), builder_proving.GetSize()},
        "flatb/proving_phase.fbs", {"flatb/"});

    // auto const *const proving_ptr = flatbuffers::GetRoot<zerauth::Proving>(
    // builder_proving.GetBufferPointer());

    // auto unpacked = proving_ptr->UnPack();

    flatbuffers::FlatBufferBuilder builder_transient;

    ASSIGN_OR_EXIT(auto const transient_challenge_hex,
                   crypto::EC_POINTS_to_hex(ec_groups, transient_points))

    // Build the Sigma table
    builder_transient.Finish(zerauth::CreateTransient(
        builder_transient,
        zerauth::CreateSetup(
            builder_transient,
            builder_transient.CreateVectorOfStrings(curve_names),
            builder_transient.CreateVectorOfStrings(
                postulate_random_points_hex),
            builder_transient.CreateVectorOfStrings(commitments_points_hex)),
        proving_offset,
        builder_transient.CreateVectorOfStrings(transient_challenge_hex)));
    debug_print_flatbuffer<zerauth::Transient>(
        {builder_transient.GetBufferPointer(), builder_transient.GetSize()},
        "flatb/transient.fbs", {"flatb/"});
  }

  // Alice execute and return the response
  // Proving : nonce, challenge
  ASSIGN_OR_EXIT(auto const response,
                 crypto::solve_challenge(secret, nonce, challenge))
  // H(nonce, challenge) : Transient =   + Setup{curve_names,
  // postulate_coordinates, commitment_coordinates} +
  ASSIGN_OR_EXIT(auto const proof,
                 crypto::verify(ec_groups, postulate_random_points, commitments,
                                transient_points, challenge, response))
  if (proof) {
    std::println("Alice proved to Bob she knows the password");
  } else {
    std::println("Verification failed");
  }

  return 0;
}
