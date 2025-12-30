#include <concepts>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <print>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <numeric>
#include <optional>
#include <random>
#include <vector>

#include "blake3.hpp"
#include <array>
#include <bit>
// Builtin for prefetching (GCC/Clang/MSVC)
#if defined(__GNUC__) || defined(__clang__)
#define PREFETCH_WRITE(ptr) __builtin_prefetch((ptr), 1, 3)
#else
#define PREFETCH_WRITE(ptr)
#endif

constexpr auto power(uint64_t base, int exp) -> uint64_t {
  if consteval {
    uint64_t res = 1UL;
    for (int idx{}; idx < exp; ++idx) {
      res *= base;
    }  // Simple algo for compile-time
    return res;
  } else {
    return static_cast<uint64_t>(
        std::pow(base, exp));  // Standard optimized version for runtime
  }
}

// 4096 ints * 4 bytes = 16KB (Safe for L1 Cache)
// 1. Cache Blocking: Use a buffer size that fits L1 Cache (e.g., 4KB =
// 1024 uint32s)
constexpr uint32_t cache_block_size = 1024U;
// q_mod 2^23 8'380'417 for Dilithium
// n_dim 512 or 1024
// secret_dimension = n_dim
// public_dimension = m_dim
static constexpr auto default_n_dim = 1U << 10U;
// q_mod  8'380'417 for Dilithium
// q=8380417 (2^23−2^13+1),
// this is for NTT
// static constexpr auto dilithium_q_mod = power(2, 23) - power(2, 13) + 1;
static constexpr auto default_q_mod = 1U << 23U;
// Goldilocks

enum PrimeType : uint64_t {
  Goldilocks = power(2, 64) - power(2, 32) + 1,
  Mersenne31 = power(2, 31) - 1,
  BabyBear = power(2, 31) - power(2, 27) + 1,
  KoalaBear = power(2, 31) - power(2, 24) + 1
};

// Goldilocks Prime
// https://github.com/logos-storage/circom-goldilocks
static constexpr auto goldilocks_prime = power(2, 64) - power(2, 32) + 1;
// Mersenne31
static constexpr auto mersenne31_prime = power(2, 31) - 1;
// BabyBear
static constexpr auto baby_bear_prime = power(2, 31) - power(2, 27) + 1;
// KoalaBear
static constexpr auto koala_bear_prime = power(2, 31) - power(2, 24) + 1;

// High-performance replacement for (val % Q)
// Input 'val' can be up to ~64 bits (e.g., result of multiplication)
constexpr auto fast_reduce(uint64_t val) -> uint32_t {
  constexpr uint32_t Q = 8380417;  // 2^23 - 2^13 + 1
  // 1. Split into lower 23 bits and upper bits
  // val = hi * 2^23 + lo
  uint32_t low_bits = val & 0x7FFFFF;  // Mask 2^23 - 1
  uint32_t high_bits = val >> 23;

  // 2. Apply identity: 2^23 = 2^13 - 1 (mod q)
  // We substitute 'hi * 2^23' with 'hi * (2^13 - 1)'
  // which equates to: (hi << 13) - hi
  int32_t result = low_bits + (high_bits << 13) - high_bits;

  // 3. Conditional Corrections
  // The result might have overflowed or be slightly negative due to
  // subtraction. We bring it back to [0, Q) range using cheap checks.

  // If result is still too large (>= 2^23), reduce one more time roughly
  // (This acts like a second round of the logic above but simplified)
  if (result >= Q) {
    result -= Q;
  }

  // Depending on the input range, you might need a stronger check:
  // This is the generic "barrett-like" cleanup for signed 32-bit math
  while (result >= (int32_t)Q) result -= Q;
  while (result < 0) result += Q;

  return (uint32_t)result;
}

void openssl_argon2id(const std::string& password, const std::string& salt,
                      unsigned char* out_buffer, size_t out_len) {
  // 1. Fetch the Argon2id Algorithm
  EVP_KDF* kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
  if (salt.size() < 8) {
    throw std::runtime_error("Salt must be at least 8 bytes");
  }
  if (kdf == NULL) {
    throw std::runtime_error(
        "OpenSSL: Argon2id not supported (Requires OpenSSL 3.2+)");
  }

  EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);  // The context holds the reference now

  if (kctx == NULL) {
    throw std::runtime_error("OpenSSL: Failed to create KDF context");
  }

  // 2. Configure Parameters (Matches Libsodium Interactive defaults)
  // Libsodium Interactive: Ops=2, Mem=64MB (65536 KB), Lanes=1
  uint32_t threads = 1;
  uint64_t mem_cost = 65536;  // in KB
  uint32_t time_cost = 2;     // Iterations
  uint32_t lanes = 1;
  OSSL_PARAM params[7];
  size_t param_idx = 0;

  params[param_idx++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_PASSWORD, (void*)password.data(), password.size());
  params[param_idx++] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
  params[param_idx++] =
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &time_cost);
  params[param_idx++] =
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
  params[param_idx++] =
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
  params[param_idx++] =
      OSSL_PARAM_construct_uint64(OSSL_KDF_PARAM_ARGON2_MEMCOST, &mem_cost);
  params[param_idx] = OSSL_PARAM_construct_end();

  // 3. Derive
  if (EVP_KDF_derive(kctx, out_buffer, out_len, params) <= 0) {
    ERR_print_errors_fp(stderr);
    EVP_KDF_CTX_free(kctx);
    throw std::runtime_error("OpenSSL: Argon2 derivation failed");
  }

  EVP_KDF_CTX_free(kctx);
}

template <typename NumType = int32_t, uint32_t modulus_q = default_q_mod>
[[nodiscard]]
constexpr auto positive_modulo(NumType const value)
    -> std::make_unsigned_t<NumType> {
  static_assert(std::has_single_bit(modulus_q),
                "modulus_q must be a power of 2");

  return static_cast<std::make_unsigned_t<NumType>>((value % modulus_q) +
                                                    modulus_q) &
         (modulus_q - 1U);
}

// A simple class to demonstrate Lattice-Based ZKP
template <uint64_t dimension_secret_n = default_n_dim,
          uint64_t dimension_public_m = dimension_secret_n / 4,
          uint32_t modulus_q = default_q_mod, int32_t eta = 2>
class LatticeZKP {
 private:
  // n_dim must always > m_dim
  static constexpr uint32_t uint32_max_value =
      std::numeric_limits<uint32_t>::max();

  // The variable eta controls the "width" of the bell curve.
  // η=2 requires 4 bits input (Used in Kyber-512).
  // η=3 requires 6 bits input (Used in Kyber-768).

  // 2 bits of entropy per coefficient
  // Matches CBD logic Requires 2*eta bits of entropy per coef
  // eta must stay between 2 and 4
  static_assert(eta >= 1 && eta <= 4, "eta must be between 1 and 4");
  static_assert(dimension_secret_n / 4 >= dimension_public_m,
                "n_dim must be greater than by at least 4 times than m_dim");

  using VectorContainerTypeN = std::array<int32_t, dimension_secret_n>;
  using VectorContainerTypeM = std::array<int32_t, dimension_public_m>;

  static auto constexpr matrix_size = dimension_public_m * dimension_secret_n;
  using MatrixContainerType = std::array<int32_t, matrix_size>;

  // Public Matrix A (m x n)
  MatrixContainerType _matrix_A{};  // Public Parameter (Shared Matrix)
  // Secret key 's' (n) and internal mask 'y' (n)
  VectorContainerTypeN _secret_key_s{};  // Secret Key (Derived from Password)
  VectorContainerTypeN _internal_mask_y{};  // Ephemeral Mask (Randomness)
  // VectorContainerTypeM _public_key_t{};     // Public Key (t = As)

  // --- Helper Math Functions ---

  // Computes res = M * v (mod q)
  [[nodiscard]]
  static auto mat_vect_mod_mult(MatrixContainerType const& matrix_M,
                                VectorContainerTypeN const& vector_v)
      -> VectorContainerTypeM {
    VectorContainerTypeM result{};
    result.fill(0);

    static_assert(matrix_M.size() == matrix_size,
                  "matrix_M size must be equal to matrix_size");
    static_assert(vector_v.size() == dimension_secret_n,
                  "vector_v size must be equal to dimension_secret_n");
    static_assert(result.size() == dimension_public_m,
                  "result size must be equal to dimension_public_m");
    static_assert(matrix_M.size() / vector_v.size() == dimension_public_m,
                  "matrix_M size must be equal to matrix_size");

    {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      // 1. Get raw pointer for speed (bypasses vector bounds checks)

      int32_t const* const __restrict__ matrix_ptr = matrix_M.data();
      int32_t const* const __restrict__ vec_ptr = vector_v.data();
      int32_t* const __restrict__ result_ptr = result.data();
      uint64_t constexpr n_dim = vector_v.size();
      uint64_t constexpr m_dim = result.size();

      for (uint32_t row_id{}; row_id < m_dim; ++row_id) {
        // OPTIMIZATION: Calculate row offset ONCE per row
        // We jump to the start of the current row
        int32_t const* const current_row = matrix_ptr + (row_id * n_dim);

        int64_t sum{};  // Use int64 to prevent overflow before modulo

// Vectorization friendly loop
#pragma clang loop vectorize(enable) interleave_count(4)
        for (uint32_t column_id = 0; column_id < n_dim; ++column_id) {
          // Access is now simple addition (ptr++), not multiplication
          sum +=
              static_cast<int64_t>(current_row[column_id]) * vec_ptr[column_id];
        }
        // Cast the result back to int32_t (safe, because result < modulus_q)
        result_ptr[row_id] =
            static_cast<int32_t>(positive_modulo<int64_t, modulus_q>(sum));
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    return result;
  }

  // Utility to print vectors
  static void printVector(std::string const& label,
                          VectorContainerTypeN const& vector_v) {
    std::print(": [ ");
    for (int32_t val : vector_v) {
      std::print("{}, ", val);
    }
    std::println("]");
  }

  static constexpr auto rejection_limit = (1U << 17U);

  static auto infinityNorm(VectorContainerTypeN const& vector_v) -> int32_t {
    int32_t max_val = 0;
    for (int32_t const val : vector_v) {
      max_val = std::max(max_val, std::abs(val));
    }
    return max_val;
  }

  explicit LatticeZKP(MatrixContainerType const& shared_matrix)
      : _matrix_A(shared_matrix) {}
  explicit LatticeZKP() = default;

 public:
  LatticeZKP(const LatticeZKP&) = delete;
  auto operator=(const LatticeZKP&) -> LatticeZKP& = delete;
  LatticeZKP(LatticeZKP&&) = delete;
  auto operator=(LatticeZKP&&) -> LatticeZKP& = delete;
  ~LatticeZKP() = default;

  static auto Create() -> std::unique_ptr<LatticeZKP> {
    std::println(
        "--- System Setup (OpenSSL) --- Matrix A generated ( pub n dim {}, "
        "secret n dim {} )",
        dimension_public_m, dimension_secret_n);
    auto lattice_zkp = std::unique_ptr<LatticeZKP>(new LatticeZKP());

    // Bit masking is faster than modulo but requires a power of 2

    // 2. DEFINE SAMPLING LOGIC
    // We sample a 32-bit integer. To avoid modulo bias, we must reject
    // values that fall in the 'remainder' zone at the top of the uint32
    // range. Range limit = (2^32) - (2^32 % q)

    // 2. Define Rejection Limit
    // We reject any random 32-bit integer that falls in the upper
    // "remainder" zone to strictly avoid modulo bias.
    // auto const limit = uint32_max_value - (uint32_max_value % modulus_q);
    static_assert(std::has_single_bit(modulus_q),
                  "modulus_q must be a power of 2");
    auto const limit =
        uint32_max_value - (uint32_max_value & (modulus_q - 1UL));

    {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      int32_t* const __restrict__ matrix_ptr = lattice_zkp->_matrix_A.data();

      // 3. Batch Allocation (The Speedup)
      // We guess we need ~5% more randomness than elements to handle
      // rejections. If the modulus is small compared to 2^32, rejections are
      // rare.
      auto constexpr buffer_count_u32 = matrix_size + (matrix_size / 16UL);
      uint64_t constexpr total_bytes = buffer_count_u32 * sizeof(uint32_t);
      std::array<uint8_t, total_bytes> random_bytes{};

      // Single System Call to OpenSSL
      if (RAND_bytes(random_bytes.data(),
                     static_cast<int>(random_bytes.size())) != 1) {
        throw std::runtime_error("Fatal: OpenSSL RNG failed.");
      }

      // 4. Fill Matrix
      uint64_t matrix_idx{};
      uint64_t byte_idx{};

      // Primary Loop: Fill using the fast buffer
      while (matrix_idx < matrix_size &&
             byte_idx + sizeof(uint32_t) <= total_bytes) {
        uint32_t val{};

        // Construct uint32_t safely using memcpy (Optimized away by compiler)
        std::memcpy(&val, &random_bytes.at(byte_idx), sizeof(uint32_t));
        byte_idx += sizeof(uint32_t);

        if (val < limit) {
          // matrix_ptr[matrix_idx++] = static_cast<int32_t>(val % modulus_q);
          // Bitwise AND is faster than modulo
          matrix_ptr[matrix_idx++] =
              static_cast<int32_t>(val & (modulus_q - 1UL));
        }
      }

      // 5. Emergency Fallback (Rare)
      // If we had extremely bad luck and rejected too many numbers,
      // fill the remaining few slots one-by-one.
      // 5. Emergency Fallback (Rare)
      while (matrix_idx < matrix_size) {
        uint32_t val = limit;

        // Use a small local buffer for the fallback
        std::array<uint8_t, sizeof(uint32_t)> fallback_buf{};

        while (val >= limit) {
          if (RAND_bytes(fallback_buf.data(),
                         static_cast<int>(fallback_buf.size())) != 1) {
            throw std::runtime_error("RNG failed");
          }
          std::memcpy(&val, fallback_buf.data(), sizeof(uint32_t));
        }
        // Bitwise AND is faster than modulo
        matrix_ptr[matrix_idx++] = static_cast<int>(val & (modulus_q - 1UL));
      }

      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    return lattice_zkp;
  }

  // replace expected
  static auto Create(MatrixContainerType const& shared_matrix)
      -> std::unique_ptr<LatticeZKP> {
    // Need new keyword to call constructor to call private constructor
    return std::unique_ptr<LatticeZKP>(new LatticeZKP(shared_matrix));
  }

  [[nodiscard]] auto matrix_A() const -> MatrixContainerType const& {
    return this->_matrix_A;
  }

  auto derive_secret(const std::string& password, const std::string& salt)
      -> VectorContainerTypeM {
    // 1. Argon2id (OpenSSL 3.2)
    // We generate a 32-byte seed
    // unsigned char seed[32];
    std::array<uint8_t, 32> seed{};

    try {
      openssl_argon2id(password, salt, seed.data(), sizeof(seed));
    } catch (const std::exception& e) {
      std::cerr << "Hardening Error: " << e.what() << std::endl;
      throw;
    }

    // 2. Randomness Expansion (BLAKE3)
    // Use your BLAKE3 implementation to expand the 32-byte seed
    // into the full vector of coefficients.

    // We need 4 bytes for every coefficient (N_DIM)
    size_t constexpr needed_bytes = dimension_secret_n * sizeof(uint32_t);
    auto const expanded_bytes = blake3::hash(seed, needed_bytes);

    // 3. Map to Lattice Coefficients
    for (size_t idx{}; idx < dimension_secret_n; idx++) {
      uint32_t val{};
      std::memcpy(&val, &expanded_bytes[idx * 4], sizeof(uint32_t));

      // Map to range [-ETA, ETA]
      static int32_t constexpr range = (2 * eta) + 1;
      // _s[i] = (val % range) - eta;
      this->_secret_key_s[idx] = static_cast<int32_t>(val % range) - eta;
    }

    return mat_vect_mod_mult(this->_matrix_A, this->_secret_key_s);
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)

  auto generateKeypair() -> VectorContainerTypeM {
    // Calculate how many bits we need for 'a' and 'b'
    // CBD logic: coeff = (sum of eta bits) - (sum of eta bits)
    // Total bits needed per coefficient = 2 * eta

    // Simplest approach for eta > 2: Use 1 full byte per coefficient
    // to avoid complex bit-packing math.
    // (Optimization: In production, you would use a bitstream reader)

    uint32_t const required_bytes = dimension_secret_n;
    std::array<uint8_t, required_bytes> random_bytes{};
    random_bytes.fill(0);

    if (RAND_bytes(random_bytes.data(),
                   static_cast<int32_t>(random_bytes.size())) != 1) {
      throw std::runtime_error("Fatal: OpenSSL RNG failed.");
    }

    // this->_secret_key_s.clear();
    // this->_secret_key_s.assign(dimension_secret_n, 0);
    this->_secret_key_s.fill(0);

    {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      int32_t* const __restrict__ secret_key_s_ptr = this->_secret_key_s.data();
      uint8_t const* const __restrict__ random_bytes_ptr = random_bytes.data();

      for (uint32_t idx = 0; idx < dimension_secret_n; ++idx) {
        uint8_t const byte = random_bytes_ptr[idx];
        auto const val = static_cast<uint32_t>(byte);

        // We need 2 * eta bits total.
        // Ensure eta is small enough for 1 byte (eta <= 4).
        // If eta=3, we need 6 bits (0..5).

        uint32_t a_sum = 0;
        uint32_t b_sum = 0;

        // Sum first 'eta' bits for a
        for (uint32_t bit = 0; bit < eta; ++bit) {
          a_sum += (val >> bit) & 1U;
        }

        // Sum next 'eta' bits for b
        for (uint32_t bit = 0; bit < eta; ++bit) {
          b_sum += (val >> (bit + eta)) & 1U;
        }
        secret_key_s_ptr[idx] =
            static_cast<int32_t>(a_sum) - static_cast<int32_t>(b_sum);
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // Compute Public Key t = A * s
    return mat_vect_mod_mult(this->_matrix_A, this->_secret_key_s);
  }

  // --- STEP 1: COMMITMENT ---
  auto createCommitment() -> VectorContainerTypeM {
    // 1. DEFINE RANGE
    // We want numbers in [-limit, +limit].
    // Total number of options = limit + limit + 1 (for zero).
    // Example: limit=5 -> -5 to +5 -> 11 options.
    constexpr auto limit = rejection_limit;
    constexpr auto range_len = (2 * limit) + 1;

    // 2. PREPARE REJECTION SAMPLING LIMIT
    // We reject random bytes that fall in the "remainder" zone of 256
    // to prevents modulo bias.
    constexpr auto cutoff = uint32_max_value - (uint32_max_value % range_len);

    this->_internal_mask_y.fill(0);

    // 3. GENERATE SECURE 'y'

    {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)

      // FIX 1: Use a byte buffer.
      // This naturally matches RAND_bytes(unsigned char*), requiring NO casts.
      std::array<uint8_t, cache_block_size * sizeof(uint32_t)> rand_buffer{};
      uint8_t* const __restrict__ rand_buffer_ptr = rand_buffer.data();
      int32_t* const __restrict__ internal_mask_y_ptr =
          this->_internal_mask_y.data();

      uint64_t generated_count = 0;

      while (generated_count < dimension_secret_n) {
        // FIX 2: Pass the byte buffer directly. No casting needed.
        if (RAND_bytes(rand_buffer.data(), rand_buffer.size()) != 1) {
          throw std::runtime_error("OpenSSL RNG failed");
        }

        // Prefetching logic
        if (generated_count + cache_block_size < dimension_secret_n) {
          PREFETCH_WRITE(
              &internal_mask_y_ptr[generated_count + cache_block_size]);
        }

        for (size_t idx = 0; idx < cache_block_size; ++idx) {
          uint32_t rand_val{};

          // FIX 3: Reconstruct the uint32_t safely.
          // Compilers optimize this memcpy to a single 'mov' instruction.
          // This satisfies strict aliasing rules better than pointer casting.
          std::memcpy(&rand_val, &rand_buffer_ptr[idx * sizeof(uint32_t)],
                      sizeof(uint32_t));

          if (rand_val <= cutoff) {
            // Optimization: Use int64_t to prevent overflow before subtraction
            internal_mask_y_ptr[generated_count] = static_cast<int32_t>(
                static_cast<int64_t>(rand_val % range_len) - limit);

            generated_count++;

            if (generated_count == dimension_secret_n) {
              break;
            }
          }
        }
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // 4. COMPUTE w = A * y mod q
    // CRITICAL: Ensure matVecMul uses positive_modulo() internally!
    // y contains negative numbers, so standard '%' will fail here.
    auto commitment_vector_w =
        mat_vect_mod_mult(this->_matrix_A, this->_internal_mask_y);

    // std::println("--- 1. Commitment (Secure) ---");
    // printVector("Mask (y) [Hidden]", y); // Don't print secrets in
    // production!
    // printVector("Commitment (w)", commitment_vector_w);

    return commitment_vector_w;
  }

  static auto deriveChallenge(std::vector<int32_t> const& commitment_w,
                              std::string const& server_nonce) -> int32_t {
    std::string data_to_hash = server_nonce;
    for (int32_t val : commitment_w) {
      data_to_hash += std::to_string(val) + ",";
    }
    uint32_t hash_val = std::hash<std::string>{}(data_to_hash);
    return static_cast<int32_t>(hash_val & 1U);  // 0 or 1
  }

  auto createResponse(int32_t const challenge)
      -> std::optional<VectorContainerTypeN> {
    // VectorType vector_z(dimension_secret_n, 0);
    VectorContainerTypeN vector_z{};
    vector_z.fill(0);

    // Calculate z = y + c * s
    {
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      int32_t* const __restrict__ ptr_z = vector_z.data();
      int32_t const* const __restrict__ ptr_y = this->_internal_mask_y.data();
      int32_t const* const __restrict__ ptr_s = this->_secret_key_s.data();
      uint32_t const dimension_secret = dimension_secret_n;

#pragma omp parallel for schedule(static)
      for (uint32_t cache_idx = 0; cache_idx < dimension_secret;
           cache_idx += cache_block_size) {
        uint32_t const end_block =
            std::min(cache_idx + cache_block_size, dimension_secret);

#pragma clang loop vectorize(enable) interleave_count(4)
        for (uint32_t idx = cache_idx; idx < end_block; ++idx) {
          ptr_z[idx] = ptr_y[idx] + (challenge * ptr_s[idx]);
        }
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }

    // --- SECURITY CHECK ---
    // Max possible value of (c * s) is (1 * eta) = 2
    constexpr auto max_cs = 1 * eta;

    // We define the safe zone as the limit minus the max shift.
    // If z falls outside this, it might leak that y was near the edge.
    constexpr auto safe_bound = rejection_limit - max_cs;

    if (infinityNorm(vector_z) > safe_bound) {
      return std::nullopt;
    }

    return vector_z;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
  using VerifyParams = struct {
    VectorContainerTypeM commitment_w;
    int32_t challenge_c;
    VectorContainerTypeN response_z;  // Size N (z = y + cs)
    VectorContainerTypeM public_key_t;
  };

  // --- VERIFICATION ---
  auto verify(VerifyParams const& params) -> bool {
    std::println("--- Verification ---");
    // 1. Compute LHS = A * z mod q
    auto lhs = mat_vect_mod_mult(this->_matrix_A, params.response_z);

    // 2. Compute RHS = w + c * t mod q
    VectorContainerTypeM rhs{};
    rhs.fill(0);

    static_assert(lhs.size() == dimension_public_m,
                  "lhs size must be equal to dimension_public_m");
    // static_assert(rhs.size() == lhs.size(),
    // "rhs size must be equal to lhs size");

    for (int32_t idx = 0; idx < rhs.size(); ++idx) {
      int32_t const val = (params.commitment_w.at(idx) +
                           (params.challenge_c * params.public_key_t.at(idx)));
      rhs.at(idx) =
          static_cast<int32_t>(positive_modulo<int64_t, modulus_q>(val));
    }

    // printVector("LHS (Az)", lhs);
    // printVector("RHS (w + ct)", rhs);

    // 3. Check Equality

    if (lhs != rhs) {
      std::print("  Mismatch details (First Element):\n");
      std::println("FAILURE: Matrix equation does not hold.");
      return false;
    }

    // 4. Check 'Smallness' of z
    // If z contains huge numbers (near q), it's likely a cheat.
    // z should be roughly size of y + c*s. Max expected ~ 4 + 2*1 = 6.
    int32_t constexpr limit = rejection_limit;
    if (!std::ranges::all_of(params.response_z, [](int32_t val) -> bool {
          return std::abs(val) <= limit;
        })) {
      std::println("FAILURE: Z vector too large.");
      return false;
    }

    return true;
  }
};

// --- STEP 2: CHALLENGE ---
static auto deriveChallenge(std::vector<int32_t> const& transient) -> int32_t {
  // 1. Serialize w into bytes
  std::string data_to_hash;
  for (int32_t val : transient) {
    data_to_hash += std::to_string(val) + ",";
  }

  uint32_t const hash_val = std::hash<std::string>{}(data_to_hash);

  // Map hash to the challenge space (0 or 1)
  // The "Challenge" is now strictly bound to the Commitment 'w'.
  // You cannot change 'w' without changing 'c'.
  // The result is guaranteed to be 0 or 1, which fits perfectly into an
  // int32_t
  return static_cast<int32_t>(hash_val & 1U);
}

auto main() -> int32_t {
  using LatticeZKP = LatticeZKP<>;
  auto&& client_ptr = LatticeZKP::Create();
  auto&& server_ptr = LatticeZKP::Create(client_ptr->matrix_A());
  auto& client_prover = *client_ptr;
  auto& server_verifier = *server_ptr;

  // 0. Setup Keys
  bool proof_generated = false;

  std::println("=== 1. REGISTRATION PHASE ===");
  // std::string user_password = "UserPassword";

  // Client derives secret 's' from password and computes public 't'
  // auto stored_public_key_t = client_prover.generateKeypair();
  auto stored_public_key_t =
      client_prover.derive_secret("password", "saltsalt");

  // In production, signatures are probabilistic. You loop until success.
  int32_t attempts = 0;
  for (; not proof_generated; ++attempts) {
    // while (not proof_generated) {
    // 1. Commitment (Prover)
    auto commitment_w = client_prover.createCommitment();

    // 2. Challenge (Verifier)
    int32_t challenge_c = deriveChallenge({'H', 'e', 'l', 'l', 'o'});

    // 3. Prover tries to create response
    // auto result = zkp.createResponse(challenge_c);
    auto z_opt = client_prover.createResponse(challenge_c);

    std::println("commitment_w size {} ", commitment_w.size());
    std::println("z_opt size {} ", z_opt.value().size());

    // 3. Response (Prover)
    if (z_opt.has_value()) {  // 4. Verify (Verifier)
      bool result = server_verifier.verify(
          {commitment_w, challenge_c, z_opt.value(), stored_public_key_t});

      if (result) {
        std::println("SUCCESS: Zero Knowledge Proof Accepted.");
        proof_generated = true;
      } else {
        std::println("FAILURE: Zero Knowledge Proof Rejected.");
        break;
      }
    } else {
      // std::println("... Client restarted protocol (Rejection Sampling) ...");
    }
  }
  std::println("attempts {}", attempts);
  return 0;
}