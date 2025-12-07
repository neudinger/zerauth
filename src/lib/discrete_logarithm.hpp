#pragma once

#include <concepts>  // for same_as
#include <expected>  // for expected
#include <format>    // for format
#include <ranges>    // for transform_view, _Partial
#include <span>      // for span

#include <flatbuffers/buffer.h>              // for Offset, GetRoot
#include <flatbuffers/flatbuffer_builder.h>  // for FlatBufferBuilder
#include <flatbuffers/string.h>              // for String
#include <flatbuffers/vector.h>              // for Vector
#include <openssl/ec.h>                      // for EC_GROUP_new_by_curve_name
#include <openssl/obj_mac.h>                 // for NID_undef
#include <openssl/objects.h>                 // for OBJ_sn2nid

#include <cstdint>  // for uint8_t
#include <string>   // for basic_string, string
#include <tuple>    // for get, tuple
#include <utility>  // for move
#include <variant>  // for tuple
#include <vector>   // for vector

#include "crypto_tools.hpp"  // for EC_GROUP_unique_ptr, EC_...
#include "lib/concepts.hpp"  // for IsStringContainer
#include "macro_tools.hpp"   // for ASSIGN_OR_UNEXPECTED
#include <type_traits>       // for invoke_result_t, is_conv...

static std::initializer_list<
    std::string_view> constexpr all_possible_curve_names{
    std::string_view("secp112r1"),
    std::string_view("secp112r2"),
    std::string_view("secp128r1"),
    std::string_view("secp128r2"),
    std::string_view("secp160k1"),
    std::string_view("secp160r1"),
    std::string_view("secp160r2"),
    std::string_view("secp192k1"),
    std::string_view("secp224k1"),
    std::string_view("secp224r1"),
    std::string_view("secp256k1"),
    std::string_view("secp384r1"),
    std::string_view("secp521r1"),
    std::string_view("prime192v1"),
    std::string_view("prime192v2"),
    std::string_view("prime192v3"),
    std::string_view("prime239v1"),
    std::string_view("prime239v2"),
    std::string_view("prime239v3"),
    std::string_view("prime256v1"),
    std::string_view("sect113r1"),
    std::string_view("sect113r2"),
    std::string_view("sect131r1"),
    std::string_view("sect131r2"),
    std::string_view("sect163k1"),
    std::string_view("sect163r1"),
    std::string_view("sect163r2"),
    std::string_view("sect193r1"),
    std::string_view("sect193r2"),
    std::string_view("sect233k1"),
    std::string_view("sect233r1"),
    std::string_view("sect239k1"),
    std::string_view("sect283k1"),
    std::string_view("sect283r1"),
    std::string_view("sect409k1"),
    std::string_view("sect409r1"),
    std::string_view("sect571k1"),
    std::string_view("sect571r1"),
    std::string_view("c2pnb163v1"),
    std::string_view("c2pnb163v2"),
    std::string_view("c2pnb163v3"),
    std::string_view("c2pnb176v1"),
    std::string_view("c2tnb191v1"),
    std::string_view("c2tnb191v2"),
    std::string_view("c2tnb191v3"),
    std::string_view("c2pnb208w1"),
    std::string_view("c2tnb239v1"),
    std::string_view("c2tnb239v2"),
    std::string_view("c2tnb239v3"),
    std::string_view("c2pnb272w1"),
    std::string_view("c2pnb304w1"),
    std::string_view("c2tnb359v1"),
    std::string_view("c2pnb368w1"),
    std::string_view("c2tnb431r1"),
    std::string_view("wap-wsg-idm-ecid-wtls1"),
    std::string_view("wap-wsg-idm-ecid-wtls3"),
    std::string_view("wap-wsg-idm-ecid-wtls4"),
    std::string_view("wap-wsg-idm-ecid-wtls5"),
    std::string_view("wap-wsg-idm-ecid-wtls6"),
    std::string_view("wap-wsg-idm-ecid-wtls7"),
    std::string_view("wap-wsg-idm-ecid-wtls8"),
    std::string_view("wap-wsg-idm-ecid-wtls9"),
    std::string_view("wap-wsg-idm-ecid-wtls10"),
    std::string_view("wap-wsg-idm-ecid-wtls11"),
    std::string_view("wap-wsg-idm-ecid-wtls12"),
    std::string_view("brainpoolP160r1"),
    std::string_view("brainpoolP160t1"),
    std::string_view("brainpoolP192r1"),
    std::string_view("brainpoolP192t1"),
    std::string_view("brainpoolP224r1"),
    std::string_view("brainpoolP224t1"),
    std::string_view("brainpoolP256r1"),
    std::string_view("brainpoolP256t1"),
    std::string_view("brainpoolP320r1"),
    std::string_view("brainpoolP320t1"),
    std::string_view("brainpoolP384r1"),
    std::string_view("brainpoolP384t1"),
    std::string_view("brainpoolP512r1"),
    std::string_view("brainpoolP512t1")};

namespace crypto {
template <typename DestType>
struct convert_to_impl;
}  // namespace crypto
namespace zerauth {
struct Proving;
}
namespace zerauth {
struct Setup;
}
namespace zerauth {
struct Transient;
}

#ifndef DISCRETE_LOGARITHM_HPP
#define DISCRETE_LOGARITHM_HPP

namespace crypto {

template <typename VerifierType>
concept VerifierRequest = std::same_as<VerifierType, zerauth::Setup> or
                          std::same_as<VerifierType, zerauth::Proving> or
                          std::same_as<VerifierType, zerauth::Transient>;

template <crypto::VerifierRequest VerifierType>
[[nodiscard]] auto flatbuffer_to_json(
    std::span<uint8_t const> const &buffer, std::string const &schema_file_name,
    std::vector<std::string> const &include_dirs = {})
    -> std::expected<std::string, std::string>;

template <crypto::VerifierRequest VerifierType>
[[nodiscard]] auto flatbuffer_to_struct(std::span<uint8_t const> const &buffer)
    -> std::expected<
        std::invoke_result_t<decltype(&flatbuffers::GetRoot<VerifierType>),
                             void const *>,
        std::string>;

[[nodiscard("Must use the returned list of curve names"), maybe_unused]]
auto list_curve_name() noexcept
    -> std::expected<std::vector<std::string>, std::string>;

template <crypto::IsStringContainer StringContainer =
              std::initializer_list<std::string_view>>
[[nodiscard]]
auto random_curves_selections(size_t size = 1,
                              StringContainer const &possible_curve_names =
                                  all_possible_curve_names) noexcept
    -> std::vector<std::string>;

[[nodiscard("Must use hex_to_BIGNUM return value")]]
auto hex_to_BIGNUM(std::string const &hex_big_num) noexcept
    -> std::expected<BN_unique_ptr, std::string>;

[[nodiscard("Must use hex_to_EC_POINT return value")]]
auto hex_to_EC_POINT(EC_GROUP_unique_ptr const &group,
                     std::string const &point_hex) noexcept
    -> std::expected<EC_POINT_unique_ptr, std::string>;

[[nodiscard("Must use get_ec_group_by_curves_name return value")]]
auto get_ec_group_by_curves_name(std::string const &curve_name) noexcept
    -> std::expected<EC_GROUP_unique_ptr, std::string>;
[[nodiscard("Must use get_ec_groups_by_curves_names return value")]]
auto get_ec_groups_by_curves_names(
    std::vector<std::string> const &curves_name) noexcept
    -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string>;

[[nodiscard("Must use get_ec_groups_by_curves_names return value")]]
auto get_ec_groups_by_curves_names(
    flatbuffers::Vector<::flatbuffers::Offset<::flatbuffers::String>> const
        *curves_name) noexcept
    -> std::expected<std::vector<EC_GROUP_unique_ptr>, std::string>;

[[nodiscard("Must use base64Decode return value")]]
auto base64Decode(std::string const &b64message) noexcept
    -> std::expected<std::vector<uint8_t>, std::string>;

[[nodiscard("Must use base64Encode return value")]]
auto base64Encode(std::span<uint8_t const> const &input) noexcept
    -> std::expected<std::string, std::string>;

template <typename DestType>
struct [[nodiscard]] convert_to_impl;

template <>
struct [[nodiscard]] convert_to_impl<std::vector<std::string>> {
  static constexpr auto _(
      flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>> const *const
          flat_buffers_vector) noexcept
      -> std::expected<std::vector<std::string>, std::string> {
    if (flat_buffers_vector == nullptr) {
      return std::vector<std::string>{};
    }
    return *flat_buffers_vector |
           std::views::transform(
               [](auto const *element) -> auto { return element->str(); }) |
           std::ranges::to<std::vector>();
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

    for (auto const &[group_name, postulate_random_point] :
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

[[nodiscard("Must use the decimal string return value"), maybe_unused]]
auto BIGNUM_to_dec(BN_unique_ptr const &bignumber) noexcept
    -> std::expected<std::string const, std::string>;

[[nodiscard("Must use the hexadecimal string return value"), maybe_unused]]
auto BIGNUM_to_hex(BN_unique_ptr const &bignumber) noexcept
    -> std::expected<std::string const, std::string>;

[[nodiscard("Must use the hexadecimal string return value")]]
auto EC_POINT_to_hex(EC_GROUP_unique_ptr const &group,
                     EC_POINT_unique_ptr const &point) noexcept
    -> std::expected<std::string, std::string>;

[[nodiscard("Must use the hexadecimal string array return value")]]
auto EC_POINTS_to_hex(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &ec_points) noexcept
    -> std::expected<std::vector<std::string>, std::string>;

[[nodiscard("Must use the returned EC_GROUP_unique_ptr"), maybe_unused]]
auto new_ec_group_by_id_curve_name(int const &curve_nid) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string>;

// long name in parameter
[[nodiscard("Must use the returned EC_GROUP_unique_ptr"), maybe_unused]]
auto new_ec_group_by_ln_curve_name(std::string const &curve_long_name) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string>;

// short name in parameter
[[nodiscard("Must use the returned EC_GROUP_unique_ptr"), maybe_unused]]
auto new_ec_group_by_sn_curve_name(std::string const &curve_short_name) noexcept
    -> std::expected<EC_GROUP_unique_ptr const, std::string>;

[[nodiscard]]
auto generate_random_group_scalar(EC_GROUP_unique_ptr const &group) noexcept
    -> std::expected<BN_unique_ptr const, std::string>;

[[nodiscard]]
auto generate_random_point(EC_GROUP_unique_ptr const &group) noexcept
    -> std::expected<EC_POINT_unique_ptr, std::string>;

[[nodiscard]]
auto generate_random_points_from(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups) noexcept
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string>;

[[nodiscard]]
auto hash_to_BIGNUM(std::vector<std::string> const &data) noexcept
    -> std::expected<BN_unique_ptr, std::string>;

// Commitment Registration

[[nodiscard]]
auto generate_commitment(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
    BN_unique_ptr const &secret) noexcept
    -> std::expected<std::vector<EC_POINT_unique_ptr>, std::string>;

[[nodiscard]]
auto generate_transient_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &postulate_random_points) noexcept
    -> std::expected<
        std::tuple<BN_unique_ptr, std::vector<EC_POINT_unique_ptr>>,
        std::string>;

[[nodiscard]]
auto generate_challenge(
    std::vector<EC_GROUP_unique_ptr> const &ec_groups,
    std::vector<EC_POINT_unique_ptr> const &commitments,
    std::vector<EC_POINT_unique_ptr> const &transient_points) noexcept
    -> std::expected<BN_unique_ptr, std::string>;

[[nodiscard]]
auto solve_challenge(BN_unique_ptr const &witness, BN_unique_ptr const &nonce,
                     BN_unique_ptr const &challenge) noexcept
    -> std::expected<BN_unique_ptr, std::string>;

using SolveChallengeParams = struct {
  std::string secret;
  std::string proving_form_b64;
};

[[nodiscard]]
auto solve_challenge(SolveChallengeParams const &params) noexcept
    -> std::expected<std::string, std::string>;

[[nodiscard]]
auto verify(std::vector<EC_GROUP_unique_ptr> const &ec_groups,
            std::vector<EC_POINT_unique_ptr> const &postulate_random_points,
            std::vector<EC_POINT_unique_ptr> const &commitments,
            std::vector<EC_POINT_unique_ptr> const &transient_points,
            BN_unique_ptr const &challenge, BN_unique_ptr const &proof) noexcept
    -> std::expected<bool, std::string>;

using VerifyParams = struct VerifyParams {
  std::string proof_hex;
  std::string transient_parameter_b64;
};

[[nodiscard]]
auto verify(VerifyParams const &params) noexcept
    -> std::expected<bool, std::string>;

[[nodiscard]]
auto create_commitment_setup(
    std::string const &secret,
    std::vector<std::string> const &curve_names_selected,
    std::string const &salt = "") noexcept
    -> std::expected<std::string, std::string>;

[[nodiscard]]
auto create_challenge(std::string const &commitment_setup_b64) noexcept
    -> std::expected<std::tuple<std::string, std::string>, std::string>;

}  // namespace crypto

[[nodiscard]]
auto flatbuffer_build_transient_builder(
    std::vector<std::string> const &curve_names,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &nonce_hex, std::string const &challenge_hex,
    std::vector<std::string> const &transient_challenge_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder;

[[nodiscard]]
auto flatbuffer_build_setup_builder(
    std::vector<std::string> const &curve_names_selected,
    std::vector<std::string> const &postulate_random_points_hex,
    std::vector<std::string> const &commitments_points_hex,
    std::string const &salt) noexcept -> flatbuffers::FlatBufferBuilder;

using ProvingParams = struct {
  std::string nonce_hex;
  std::string challenge_hex;
  std::string salt;
};

auto flatbuffer_build_proving_builder(ProvingParams const &params) noexcept
    -> flatbuffers::FlatBufferBuilder;

#endif /* DISCRETE_LOGARITHM_HPP */
