#include <expected>  // for expected
#include <span>      // for span

#include <flatbuffers/buffer.h>                   // for Offset
#include <flatbuffers/flatbuffer_builder.h>       // for FlatBufferBuilder
#include <flatbuffers/proving_phase_generated.h>  // for CreateProving
#include <flatbuffers/setup_phase_generated.h>    // for Setup
#include <flatbuffers/string.h>                   // for String
#include <openssl/ec.h>                           // for EC_get_builtin_curves
#include <openssl/objects.h>                      // for OBJ_nid2ln

#include <print>  // for println

#include <algorithm>         // for sample
#include <cstdlib>           // for EXIT_FAILURE, EXIT_...
#include <cstring>           // for memcpy
#include <exception>         // for exception
#include <initializer_list>  // for initializer_list
#include <iterator>          // for back_inserter
#include <random>            // for random_device, defa...
#include <string>            // for basic_string, string
#include <string_view>       // for string_view
#include <tuple>             // for get, tuple, make_tuple
#include <utility>           // for move
#include <vector>            // for vector

#include "lib/concepts.hpp"            // for IsStringContainer
#include "lib/crypto_tools.hpp"        // for EC_POINT_unique_ptr
#include "lib/discrete_logarithm.hpp"  // for convert_to, base64D...
#include "lib/macro_tools.hpp"         // for ASSIGN_OR_UNEXPECTED
#include "lib/tools.hpp"               // for generate_random_string
namespace zerauth {
struct Transient;
}  // namespace zerauth

#if defined(__EMSCRIPTEN__) || defined(__EMSCRIPTEN_BUILD__)
#include <emscripten/emscripten.h>
// #include <GLES3/gl3.h>
#include <emscripten/bind.h>
#else
#endif

#if defined(__EMSCRIPTEN__) || defined(__EMSCRIPTEN_BUILD__)

using ExpectedStringResult = struct {
  bool is_success;
  std::string value;
  std::string error;
};

static auto create_commitment_setup_js(
    std::string const &secret,
    std::vector<std::string> const &curve_names_selected,
    std::string const &salt = "") -> ExpectedStringResult {
  auto const result_or_error =
      crypto::create_commitment_setup(secret, curve_names_selected, salt);
  return ExpectedStringResult{.is_success = result_or_error.has_value(),
                              .value = result_or_error.value_or(""),
                              .error = result_or_error.error_or("")};
}

static auto solve_challenge_js(std::string const &secret,
                               std::string const &proving_form_b64)
    -> ExpectedStringResult {
  auto const result_or_error = crypto::solve_challenge(
      {.secret = secret, .proving_form_b64 = proving_form_b64});
  return ExpectedStringResult{.is_success = result_or_error.has_value(),
                              .value = result_or_error.value_or(""),
                              .error = result_or_error.error_or("")};
}

using ExpectedBoolResult = struct {
  bool is_success;
  bool value;
  std::string error;
};

static auto verify_js(std::string const &proof_hex,
                      std::string const &transient_parameter_b64)
    -> ExpectedBoolResult {
  auto const result_or_error =
      crypto::verify({.proof_hex = proof_hex,
                      .transient_parameter_b64 = transient_parameter_b64});
  return ExpectedBoolResult{.is_success = result_or_error.has_value(),
                            .value = result_or_error.value_or(false),
                            .error = result_or_error.error_or("")};
}

using StringPair = struct {
  std::string first;
  std::string second;
};

using ExpectedTupleStringResult = struct {
  bool is_success;
  StringPair value;
  std::string error;
};

static auto create_challenge_js(std::string const &buffer_setup_b64)
    -> ExpectedTupleStringResult {
  auto const result_or_error = crypto::create_challenge(buffer_setup_b64);
  auto const &[first, second] =
      result_or_error.value_or(std::make_tuple("", ""));
  return ExpectedTupleStringResult{
      .is_success = result_or_error.has_value(),
      .value = StringPair{.first = first, .second = second},
      .error = result_or_error.error_or("")};
}

static auto random_curves_selections_js(size_t size)
    -> std::vector<std::string> {
  return crypto::random_curves_selections(size);
}

// Embind allows you to expose C++ functions to JavaScript
EMSCRIPTEN_BINDINGS(Zerauth) {
  emscripten::value_object<StringPair>("StringPair")
      .field("first", &StringPair::first)
      .field("second", &StringPair::second);
  emscripten::value_object<ExpectedBoolResult>("ExpectedBoolResult")
      .field("isSuccess", &ExpectedBoolResult::is_success)
      .field("value", &ExpectedBoolResult::value)
      .field("error", &ExpectedBoolResult::error);
  emscripten::value_object<ExpectedStringResult>("ExpectedStringResult")
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
  emscripten::register_vector<std::string>("StringList");
  emscripten::function("random_curves_selections",
                       &random_curves_selections_js);
  emscripten::function("create_commitment_setup", &create_commitment_setup_js);
  emscripten::function("create_challenge", &create_challenge_js);
  emscripten::function("solve_challenge", &solve_challenge_js);
  emscripten::function("verify", &verify_js);
}
#else

auto test() -> int {
  /* ================== Enrollment step Start ================== */

#pragma region Setup Enrollment Step

  auto const salt = crypto::generate_random_string(8);

  auto const buffer_setup_b64_or_error = crypto::create_commitment_setup(
      "password", crypto::random_curves_selections(1), salt);

  if (not buffer_setup_b64_or_error.has_value()) {
    std::println("Failed to create commitment setup");
    return EXIT_FAILURE;
  }

  auto const &&buffer_setup_b64 = std::move(buffer_setup_b64_or_error.value());

  // The Prover send to the verifier the postulate and the commitments (in
  // enrollment process) The Verifier generate the transient challenge and
  // send it to the prover

#pragma endregion Setup Enrollment Step

  // Alice ask bob to prove that she knows the password, so bob generate the
  // transient challenge (transient_points) based on the
  // postulate_random_points placed on their respective elliptic curve group
  // and
  // send the transient nonce to Alice
#pragma region Challenge Step
  // DEBUG
  {
    auto const buffer_setup_or_error = crypto::base64Decode(buffer_setup_b64);
    if (not buffer_setup_or_error.has_value()) {
      std::println("Failed to decode buffer setup");
      return EXIT_FAILURE;
    }
    auto const &&buffer_setup = std::move(buffer_setup_or_error.value());

    auto const json_setup_or_error = crypto::flatbuffer_to_json<zerauth::Setup>(
        buffer_setup, "flatb/setup_phase.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}", json_setup_or_error.has_value()
                                               ? json_setup_or_error.value()
                                               : json_setup_or_error.error());
  }

  auto const challenge_phase_or_error =
      crypto::create_challenge(buffer_setup_b64);

  if (not challenge_phase_or_error.has_value()) {
    std::println("Failed to create challenge");
    return EXIT_FAILURE;
  }

  auto const &&challenge_phase = std::move(challenge_phase_or_error.value());
  auto const &[proving_form_b64, transient_parameter_b64] = challenge_phase;

  // DEBUG
  {
    auto const buffer_proving_form_or_error =
        crypto::base64Decode(proving_form_b64);
    if (not buffer_proving_form_or_error.has_value()) {
      std::println("Failed to decode buffer proving form");
      return EXIT_FAILURE;
    }
    auto const &&buffer_proving_form =
        std::move(buffer_proving_form_or_error.value());

    auto const json_setup = crypto::flatbuffer_to_json<zerauth::Proving>(
        buffer_proving_form, "flatb/proving_phase.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}", json_setup.has_value()
                                               ? json_setup.value()
                                               : json_setup.error());
  }

  // DEBUG
  {
    auto const buffer_transient_form_or_error =
        crypto::base64Decode(transient_parameter_b64);
    if (not buffer_transient_form_or_error.has_value()) {
      std::println("Failed to decode buffer transient form");
      return EXIT_FAILURE;
    }
    auto const &&buffer_transient_form =
        std::move(buffer_transient_form_or_error.value());

    auto const json_setup = crypto::flatbuffer_to_json<zerauth::Transient>(
        buffer_transient_form, "flatb/transient.fbs", {"flatb/"});

    std::println("--- json_setup ---\n{}", json_setup.has_value()
                                               ? json_setup.value()
                                               : json_setup.error());
  }
#pragma region Challenge Step

#pragma region Solving Step

  auto const proof_hex_or_error = crypto::solve_challenge(
      {.secret = "password", .proving_form_b64 = proving_form_b64});

  if (not proof_hex_or_error.has_value()) {
    std::println("Failed to solve challenge");
    return EXIT_FAILURE;
  }

  auto const &&proof_hex = std::move(proof_hex_or_error.value());

#pragma region Solving Step

  // DEBUG
  {
    std::println("Proof is ({})", proof_hex);
  }

#pragma region Verification Step

  auto const proof_or_error =
      crypto::verify({.proof_hex = proof_hex,
                      .transient_parameter_b64 = transient_parameter_b64});

  if (not proof_or_error.has_value()) {
    std::println("Failed to verify");
    return EXIT_FAILURE;
  }

  auto const &&proof = std::move(proof_or_error.value());

  if (proof) {
    std::println("Alice proved to Bob she knows the password");
  } else {
    std::println("Verification failed");
  }
#pragma region Verification Step
  return EXIT_SUCCESS;
}

auto main(int argc, const char **argv) -> int {
  try {
    return test();
  } catch (const std::exception &e) {
    // Handle the exception (e.g., print to stderr)
    // Note: Using fprintf/fputs is safer here than std::println
    // in case the exception was caused by the output stream itself.
    // std::println("Unhandled exception: {}", e.what());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
#endif
