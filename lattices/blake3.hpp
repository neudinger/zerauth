#include <ranges>
#include <span>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

#include <array>
#include <bit>

#if defined(__EMSCRIPTEN__) || defined(__EMSCRIPTEN_BUILD__)
#define attribute_alignas alignas(16)
#else
#define attribute_alignas alignas(64)
#endif

#if defined(_MSC_VER)
#define attribute_force_inline __forceinline
#elif defined(__clang__) || defined(__GNUC__)
#define attribute_force_inline __attribute__((always_inline)) inline
#else
#define attribute_force_inline inline
#endif

#if defined(__EMSCRIPTEN__) || defined(__clang__) || defined(__GNUC__)
#define attribute_hot __attribute__((hot))
#define attribute_pure __attribute__((pure))
#define attribute_const __attribute__((const))
#else
#define attribute_hot
#define attribute_pure
#define attribute_const
#endif

namespace blake3 {

namespace detail {

// --- Concepts ---

// Ensures the input is a contiguous range of 1-byte elements.
// Accepts: std::string, std::string_view, std::vector<uint8_t>,
// std::vector<char>, std::span, std::array<uint8_t>, etc.
template <typename T>
concept ByteContiguousRange = std::ranges::contiguous_range<T> &&
                              (sizeof(std::ranges::range_value_t<T>) == 1);

// --- Constants & Configuration ---
// chaining_value_ints
constexpr size_t k_chaining_value_ints = 8UL;
// block_len_bytes
constexpr size_t k_block_len_bytes = 64UL;
// chunk_len_bytes
constexpr size_t k_chunk_len_bytes = 1024UL;

// bytes_per_word
constexpr size_t k_bytes_per_word = sizeof(uint32_t);
// bits_per_byte
constexpr size_t k_bits_per_byte = std::numeric_limits<uint8_t>::digits;
// half_block_bytes
constexpr size_t k_half_block_bytes = 32UL;

enum RotationConstants : uint8_t {
  ROT_7 = 7U,
  ROT_8 = 8U,
  ROT_12 = 12U,
  ROT_16 = 16U,
};

// Bitwise constants
enum BitwiseConstants : uint32_t {
  SHIFT_8 = 8U,
  SHIFT_16 = 16U,
  SHIFT_24 = 24U,
  SHIFT_32 = 32U,
  MASK_64_LOW_32 = 0xFFFFFFFFU,
};

constexpr std::array<uint32_t, k_chaining_value_ints> k_initial_vector = {
    0x6A09E667U, 0xBB67AE85U, 0x3C6EF372U, 0xA54FF53AU,
    0x510E527FU, 0x9B05688CU, 0x1F83D9ABU, 0x5BE0CD19U};

// Message permutation schedule
constexpr size_t k_block_words_count = 16UL;
constexpr size_t k_msg_schedule_rounds = 7UL;

constexpr std::array<uint8_t, k_msg_schedule_rounds * k_block_words_count>
    k_msg_schedule_byte_offsets = {
        // Round 0: {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} * 4
        0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
        // Round 1: {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8} * 4
        8, 24, 12, 40, 28, 0, 16, 52, 4, 44, 48, 20, 36, 56, 60, 32,
        // Round 2: {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1} * 4
        12, 16, 40, 48, 52, 8, 28, 56, 24, 20, 36, 0, 44, 60, 32, 4,
        // Round 3: {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6} * 4
        40, 28, 48, 36, 56, 12, 52, 60, 16, 0, 44, 8, 20, 32, 4, 24,
        // Round 4: {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4} * 4
        48, 52, 36, 44, 60, 40, 56, 32, 28, 8, 20, 12, 0, 4, 24, 16,
        // Round 5: {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7} * 4
        36, 56, 44, 20, 32, 48, 60, 4, 52, 12, 0, 40, 8, 24, 16, 28,
        // Round 6: {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13} * 4
        44, 60, 20, 0, 4, 36, 32, 24, 56, 40, 8, 48, 12, 16, 28, 52};

enum Flags : uint8_t {
  FLAG_CHUNK_INIT = 0U,
  FLAG_CHUNK_START = 1U << 0U,
  FLAG_CHUNK_END = 1U << 1U,
  FLAG_PARENT = 1U << 2U,
  FLAG_ROOT = 1U << 3U,
};

// --- Load / Store Utilities ---

template <typename T>
constexpr auto as_uint8_span(std::span<T> span) -> std::span<const uint8_t> {
  auto bytes = std::as_bytes(span);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  return {reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()};
}

attribute_force_inline constexpr auto load_le32(
    uint8_t const* const __restrict__ src) noexcept -> uint32_t {
  if consteval {
    // Compile-time path (manual shift)
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    return static_cast<uint32_t>(src[0]) |
           (static_cast<uint32_t>(src[1]) << BitwiseConstants::SHIFT_8) |
           (static_cast<uint32_t>(src[2]) << BitwiseConstants::SHIFT_16) |
           (static_cast<uint32_t>(src[3]) << BitwiseConstants::SHIFT_24);
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  } else {
    // Runtime path (safe memcpy)
    // NOLINTNEXTLINE(cppcoreguidelines-init-variables)
    uint32_t word;
    // Compiles to a single unaligned load instruction on x86/WASM
    std::memcpy(&word, src, sizeof(word));
    if constexpr (std::endian::native == std::endian::little) {
      return word;  // Assumes Little Endian host (WASM is LE)
    } else {
#if __cpp_lib_byteswap >= 202110L
      return std::byteswap(word);
#else
      // Fallback for C++20 without <bit> byteswap support
      return ((word & 0xFF000000U) >> BitwiseConstants::SHIFT_24) |
             ((word & 0x00FF0000U) >> BitwiseConstants::SHIFT_8) |
             ((word & 0x0000FF00U) << BitwiseConstants::SHIFT_8) |
             ((word & 0x000000FFU) << BitwiseConstants::SHIFT_24);
#endif
    }
  }
}

constexpr auto store_word_le(std::span<uint8_t> destination,
                             uint32_t const word) noexcept -> void {
  if consteval {
    destination[0] = static_cast<uint8_t>(word);
    destination[1] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_8);
    destination[2] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_16);
    destination[3] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_24);
  } else {
    if constexpr (std::endian::native == std::endian::little) {
      std::memcpy(destination.data(), &word, sizeof(word));
    } else {
      destination[0] = static_cast<uint8_t>(word);
      destination[1] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_8);
      destination[2] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_16);
      destination[3] = static_cast<uint8_t>(word >> BitwiseConstants::SHIFT_24);
    }
  }
}

// --- Core Math ---

// NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index,
// cppcoreguidelines-avoid-magic-numbers)

// Helper for the "G" function logic to ensure strictly inlineable arithmetic
#define MIX(a, b, c, d, x, y)                                             \
  do {                                                                    \
    state[a] = state[a] + state[b] + (x);                                 \
    state[d] = std::rotr(state[d] ^ state[a], RotationConstants::ROT_16); \
    state[c] = state[c] + state[d];                                       \
    state[b] = std::rotr(state[b] ^ state[c], RotationConstants::ROT_12); \
    state[a] = state[a] + state[b] + (y);                                 \
    state[d] = std::rotr(state[d] ^ state[a], RotationConstants::ROT_8);  \
    state[c] = state[c] + state[d];                                       \
    state[b] = std::rotr(state[b] ^ state[c], RotationConstants::ROT_7);  \
  } while (false)

// Helper to load message words using your existing load_le32
// We use a macro here to force the inlining of the offset calculation
#define MSG(offset_idx) \
  load_le32(message_bytes + k_msg_schedule_byte_offsets[base + offset_idx])

template <size_t RoundIndex>
attribute_force_inline constexpr void round_function(
    std::array<uint32_t, k_block_words_count>& state,
    uint8_t const* __restrict__ message_bytes) noexcept {
  // Column Step
  // The compiler can easily see that these 4 G calls are independent
  // and can vectorize them into 4-wide SIMD instructions.
  constexpr size_t base = RoundIndex * 16;

  // We load all 16 words into local registers immediately.
  // This allows the CPU to "fire and forget" 16 load instructions
  // before the heavy arithmetic creates dependency stalls.

  auto message_0 = MSG(0);
  auto message_1 = MSG(1);
  auto message_2 = MSG(2);
  auto message_3 = MSG(3);
  auto message_4 = MSG(4);
  auto message_5 = MSG(5);
  auto message_6 = MSG(6);
  auto message_7 = MSG(7);
  auto message_8 = MSG(8);
  auto message_9 = MSG(9);
  auto message_10 = MSG(10);
  auto message_11 = MSG(11);
  auto message_12 = MSG(12);
  auto message_13 = MSG(13);
  auto message_14 = MSG(14);
  auto message_15 = MSG(15);

  MIX(0, 4, 8, 12, message_0, message_1);
  MIX(1, 5, 9, 13, message_2, message_3);
  MIX(2, 6, 10, 14, message_4, message_5);
  MIX(3, 7, 11, 15, message_6, message_7);

  // Diagonal Step
  MIX(0, 5, 10, 15, message_8, message_9);
  MIX(1, 6, 11, 12, message_10, message_11);
  MIX(2, 7, 8, 13, message_12, message_13);
  MIX(3, 4, 9, 14, message_14, message_15);
}
#undef MSG
#undef MIX

// NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index,
// cppcoreguidelines-avoid-magic-numbers)

// NOLINTBEGIN(cppcoreguidelines-pro-type-member-init, hicpp-member-init,
// cppcoreguidelines-pro-bounds-constant-array-index,
// cppcoreguidelines-pro-type-reinterpret-cast,
// cppcoreguidelines-avoid-magic-numbers)
// Template parameter 'IsFullBlock' allows the compiler to
// completely delete the padding logic in the 'true' case.
template <bool IsFullBlock>
attribute_hot constexpr auto compress_block(
    std::array<uint32_t, k_chaining_value_ints> const& chaining_value,
    std::span<uint8_t const> block, uint64_t const counter, Flags const flags,
    std::span<uint32_t, k_block_words_count> destination) noexcept -> void {
  // NOLINTBEGIN(cppcoreguidelines-pro-type-member-init)
  attribute_alignas std::array<uint32_t, k_block_words_count> state;

  // We only initialize the padding buffer if we are in the "Safe Path".
  // In the "Fast Path" (IsFullBlock=true), this variable is optimized away.
  attribute_alignas std::array<uint8_t, k_block_len_bytes> padded_block_storage;

  // Default to zero-copy: point directly to input data
  uint8_t const* message_ptr = block.data();

  // --- 1. Initialize State ---
  if consteval {
    std::copy_n(chaining_value.begin(), 8, state.begin());
  } else {
    // Vectorized initialization
    std::memcpy(state.data(), chaining_value.data(), 32);
  }

  // Use constants directly for IV to avoid memory load latency
  state[8] = k_initial_vector[0];
  state[9] = k_initial_vector[1];
  state[10] = k_initial_vector[2];
  state[11] = k_initial_vector[3];

  // Immediately follow with dynamic parameters
  state[12] = static_cast<uint32_t>(counter);
  state[13] = static_cast<uint32_t>(counter >> 32);
  state[14] = static_cast<uint32_t>(block.size());
  state[15] = static_cast<uint32_t>(flags);

  // --- 2. Handle Padding (Compile-Time Switch) ---

  if constexpr (!IsFullBlock) {
    if (block.size() < k_block_len_bytes) {
      if consteval {
        std::ranges::copy(block, padded_block_storage.begin());
        std::ranges::fill(std::span(padded_block_storage).subspan(block.size()),
                          uint8_t{});
      } else {
        std::memcpy(padded_block_storage.data(), block.data(), block.size());
        std::memset(padded_block_storage.data() + block.size(), uint8_t{},
                    k_block_len_bytes - block.size());
      }
      message_ptr = padded_block_storage.data();
    }
  }

  // --- 3. Rounds ---
  state[12] = static_cast<uint32_t>(counter);
  state[13] = static_cast<uint32_t>(counter >> 32);
  state[14] = static_cast<uint32_t>(block.size());
  state[15] = static_cast<uint32_t>(flags);

  // Unrolled rounds with HARDCODED permutation types (from Optimization A)
  round_function<0>(state, message_ptr);
  round_function<1>(state, message_ptr);
  round_function<2>(state, message_ptr);
  round_function<3>(state, message_ptr);
  round_function<4>(state, message_ptr);
  round_function<5>(state, message_ptr);
  round_function<6>(state, message_ptr);

  // --- 4. Finalize ---
#pragma clang loop unroll(full)
  for (size_t idx{}; idx < 8U; ++idx) {
    state[idx] ^= state[idx + 8U];
    state[idx + 8] ^= chaining_value[idx];
  }

  if consteval {
    std::ranges::copy(state, destination.begin());
  } else {
    std::memcpy(destination.data(), state.data(), sizeof(state));
  }
  // NOLINTEND(cppcoreguidelines-pro-type-member-init)
}
// NOLINTEND(cppcoreguidelines-pro-type-member-init, hicpp-member-init,
// cppcoreguidelines-pro-bounds-constant-array-index,
// cppcoreguidelines-pro-type-reinterpret-cast,
// cppcoreguidelines-avoid-magic-numbers)

// --- Output Class ---

class output_t {
  attribute_alignas std::array<uint32_t, k_chaining_value_ints>
      _input_chaining_value{};
  attribute_alignas std::array<uint8_t, k_chunk_len_bytes> _block_storage{};
  size_t _block_len_bytes{};
  uint8_t _flags{};

 public:
  constexpr output_t(
      std::array<uint32_t, k_chaining_value_ints> const& chaining_value,
      std::span<uint8_t const> block_bytes, uint8_t flags)
      : _input_chaining_value{chaining_value},
        _block_len_bytes(block_bytes.size()),
        _flags(flags) {
    std::ranges::copy(block_bytes, this->_block_storage.begin());
  }

  constexpr auto fill_destination(std::span<uint8_t> destination) const noexcept
      -> void {
    size_t const current_len = destination.size();
    size_t output_block_counter{};
    size_t offset_pos{};
    // OPTIMIZATION: Reusable, aligned scratch buffer for compressor output.
    // This avoids reconstructing the array object on every loop iteration.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
    attribute_alignas std::array<uint32_t, k_block_words_count>
        compress_scratch;

    while (offset_pos < current_len) {
      std::span<uint8_t const> const block_view{this->_block_storage.data(),
                                                this->_block_len_bytes};

      compress_block<false>(
          this->_input_chaining_value, block_view, output_block_counter++,
          Flags(this->_flags | Flags::FLAG_ROOT), compress_scratch);

      size_t const remaining_bytes = current_len - offset_pos;
      size_t const chunk_size = (remaining_bytes < k_block_len_bytes)
                                    ? remaining_bytes
                                    : k_block_len_bytes;
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index,
      // cppcoreguidelines-pro-bounds-pointer-arithmetic)
      if consteval {
// Keep the shift logic for Compile-Time (constexpr)
#pragma clang loop unroll(full)
        for (size_t index{}; index < chunk_size; ++index) {
          auto const word_index = index / k_bytes_per_word;
          auto const byte_shift =
              k_bits_per_byte * (index & (k_bytes_per_word - 1UL));
          auto const& word = compress_scratch[word_index];
          destination[offset_pos + index] =
              static_cast<uint8_t>(word >> byte_shift);
        }
      } else {
        // Runtime Optimization:
        // Since WASM is Little Endian, the uint32 array is already
        // laid out as the correct byte sequence.
        if constexpr (std::endian::native == std::endian::little) {
          std::memcpy(destination.data() + offset_pos, compress_scratch.data(),
                      chunk_size);
        } else {
          // Fallback for Big Endian architectures (rare)
          for (size_t index{}; index < chunk_size; ++index) {
            auto const word_index = index / k_bytes_per_word;
            auto const byte_shift =
                k_bits_per_byte * (index & (k_bytes_per_word - 1UL));
            destination[offset_pos + index] = static_cast<uint8_t>(
                compress_scratch[word_index] >> byte_shift);
          }
        }
      }
      // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index,
      // cppcoreguidelines-pro-bounds-pointer-arithmetic)

      offset_pos += chunk_size;
    }
  }

  template <size_t N>
  [[nodiscard]] constexpr auto extract_array() const noexcept
      -> std::array<uint8_t, N> {
    std::array<uint8_t, N> result_array{};
    fill_destination(result_array);
    return result_array;
  }
};

// --- Chunk State Class ---

class chunk_state_t {
  attribute_alignas std::array<uint32_t, k_chaining_value_ints>
      _chaining_value{};
  attribute_alignas std::array<uint8_t, k_chunk_len_bytes> _buffer{};
  uint64_t _chunk_counter{};
  size_t _buffer_len_bytes{};
  uint8_t _blocks_compressed_count{};
  Flags _flags{};

 public:
  constexpr chunk_state_t(
      std::array<uint32_t, k_chaining_value_ints> const& key,
      uint64_t chunk_counter, Flags flags = Flags::FLAG_CHUNK_INIT)
      : _chaining_value{key}, _chunk_counter(chunk_counter), _flags(flags) {}

  [[nodiscard]] constexpr auto total_len() const noexcept -> size_t {
    return (static_cast<size_t>(this->_blocks_compressed_count) *
            k_block_len_bytes) +
           this->_buffer_len_bytes;
  }

  [[nodiscard]] constexpr auto get_start_flag() const noexcept -> uint8_t {
    return this->_blocks_compressed_count == uint8_t{} ? Flags::FLAG_CHUNK_START
                                                       : uint8_t{};
  }

  template <ByteContiguousRange Range>
  constexpr auto update(Range const& input_data) noexcept -> void {
    // 1. Basic Setup
    auto const* data_ptr = std::ranges::data(input_data);
    size_t input_len = std::ranges::size(input_data);

    // For ByteContiguousRange, size() is effectively byte length because
    // sizeof(T)==1. However, we track 'offset' to iterate cleanly.
    size_t offset = 0;

    // OPTIMIZATION: Reusable, aligned scratch buffer.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
    attribute_alignas std::array<uint32_t, k_block_words_count>
        compress_scratch;

    // --- 1. Fill Buffer (Partial Data) ---
    if (this->_buffer_len_bytes > 0) {
      size_t const needed = k_block_len_bytes - this->_buffer_len_bytes;
      size_t const take = (needed < input_len) ? needed : input_len;
      auto dest_span =
          std::span{this->_buffer}.subspan(this->_buffer_len_bytes, take);

      if consteval {
        // Safe for char/uint8_t mismatch: std::copy_n casts elements
        // individually
        std::copy_n(data_ptr + offset, take, dest_span.begin());
      } else {
        // Runtime fast path
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* byte_ptr = reinterpret_cast<uint8_t const*>(data_ptr);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::memcpy(dest_span.data(), byte_ptr + offset, take);
      }

      this->_buffer_len_bytes += take;
      offset += take;
      input_len -= take;

      if (this->_buffer_len_bytes == k_block_len_bytes) {
        std::span<uint8_t const> const block_view{this->_buffer.data(),
                                                  k_block_len_bytes};

        compress_block<true>(
            this->_chaining_value, block_view, this->_chunk_counter,
            Flags(this->_flags | get_start_flag()), compress_scratch);

        if consteval {
          std::copy_n(compress_scratch.begin(), k_chaining_value_ints,
                      this->_chaining_value.begin());
        } else {
          std::memcpy(this->_chaining_value.data(), compress_scratch.data(),
                      k_chaining_value_ints * k_bytes_per_word);
        }
        this->_blocks_compressed_count++;
        this->_buffer_len_bytes = 0UL;
      }
    }

    // --- 2. Fast Path (Full Blocks) ---
    while (input_len >= k_block_len_bytes) [[likely]] {
      if consteval {
        // CONSTEXPR PATH
        // We cannot reinterpret_cast. We must check types.
        using ValT = std::ranges::range_value_t<Range>;

        if constexpr (std::is_same_v<ValT, uint8_t>) {
          // Input is ALREADY uint8_t. Zero-copy is safe.
          auto const* ptr = data_ptr + offset;
          compress_block<true>(this->_chaining_value, {ptr, k_block_len_bytes},
                               this->_chunk_counter,
                               Flags(this->_flags | get_start_flag()),
                               compress_scratch);

          std::copy_n(compress_scratch.begin(), k_chaining_value_ints,
                      this->_chaining_value.begin());
        } else {
          // Input is char/signed char. We CANNOT cast pointer to uint8_t*.
          // We MUST copy to a temporary buffer first to type-pun safely.
          // Note: We use _buffer as a temporary scratchpad since it's empty
          // here (loop condition).
          std::copy_n(data_ptr + offset, k_block_len_bytes,
                      this->_buffer.begin());

          compress_block<true>(
              this->_chaining_value, {this->_buffer.data(), k_block_len_bytes},
              this->_chunk_counter, Flags(this->_flags | get_start_flag()),
              compress_scratch);

          std::copy_n(compress_scratch.begin(), k_chaining_value_ints,
                      this->_chaining_value.begin());
        }
      } else {
        // RUNTIME PATH (Zero-Copy for ALL types via reinterpret_cast)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* byte_ptr = reinterpret_cast<uint8_t const*>(data_ptr);

        compress_block<true>(
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            this->_chaining_value, {byte_ptr + offset, k_block_len_bytes},
            this->_chunk_counter, Flags(this->_flags | get_start_flag()),
            compress_scratch);

        std::memcpy(this->_chaining_value.data(), compress_scratch.data(),
                    k_chaining_value_ints * k_bytes_per_word);
      }

      this->_blocks_compressed_count++;
      offset += k_block_len_bytes;
      input_len -= k_block_len_bytes;
    }

    if (input_len > 0) {
      if consteval {
        std::copy_n(data_ptr + offset, input_len, this->_buffer.begin());
      } else {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* byte_ptr = reinterpret_cast<uint8_t const*>(data_ptr);
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
        std::memcpy(this->_buffer.data(), byte_ptr + offset, input_len);
      }
      this->_buffer_len_bytes = input_len;
    }
  }

  [[nodiscard]] constexpr auto output_chaining_value() const noexcept
      -> std::array<uint32_t, k_block_words_count> {
    auto const current_flags =
        Flags(static_cast<unsigned>(this->_flags) |
              static_cast<unsigned>(get_start_flag()) |
              static_cast<unsigned>(Flags::FLAG_CHUNK_END));
    std::span<uint8_t const> block_view{_buffer.data(),
                                        this->_buffer_len_bytes};
    // OPTIMIZATION: Reusable, aligned scratch buffer for compressor output.
    // This avoids reconstructing the array object on every loop iteration.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
    attribute_alignas std::array<uint32_t, k_block_words_count>
        compress_scratch;

    compress_block<false>(this->_chaining_value, block_view,
                          this->_chunk_counter, current_flags,
                          compress_scratch);
    return compress_scratch;
  }

  struct root_props_t {
    attribute_alignas std::array<uint32_t, k_chaining_value_ints>
        chaining_values{};
    std::span<uint8_t const> block;
    uint64_t counter{};
    uint8_t flags{};
  };

  [[nodiscard]] constexpr auto get_root_props() const noexcept -> root_props_t {
    return {.chaining_values = this->_chaining_value,
            .block = std::span<uint8_t const>{_buffer.data(),
                                              this->_buffer_len_bytes},
            .counter = this->_chunk_counter,
            .flags = static_cast<uint8_t>(
                static_cast<unsigned>(_flags) |
                static_cast<unsigned>(get_start_flag()) |
                static_cast<unsigned>(Flags::FLAG_CHUNK_END))};
  }
};

// --- Hasher Class ---

class hasher_t {
  static constexpr size_t k_max_stack_depth = 54;

  attribute_alignas std::array<uint32_t, k_chaining_value_ints> _key{};
  attribute_alignas
      std::array<std::array<uint32_t, k_chaining_value_ints>, k_max_stack_depth>
          _chaining_value_stack{};
  chunk_state_t _chunk_state;
  uint8_t _stack_len{};
  uint64_t _total_chunks_count{};

  constexpr void push_stack(
      // NOLINTBEGIN(cppcoreguidelines-pro-bounds-constant-array-index,
      // cppcoreguidelines-pro-bounds-pointer-arithmetic)
      std::array<uint32_t, k_block_words_count> const& chunk_output) {
    uint64_t current_chunks = this->_total_chunks_count;
    attribute_alignas std::array<uint32_t, k_chaining_value_ints>
        right_chaining_value;
    // OPTIMIZATION: Reusable, aligned scratch buffer for compressor output.
    // This avoids reconstructing the array object on every loop iteration.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init, hicpp-member-init)
    attribute_alignas std::array<uint32_t, k_block_words_count>
        compress_scratch;

    if consteval {
      std::copy_n(chunk_output.begin(), k_chaining_value_ints,
                  right_chaining_value.begin());
    } else {
      std::memcpy(right_chaining_value.data(), chunk_output.data(),
                  k_chaining_value_ints);
    }

    while ((current_chunks & 1U) != 0U) {
      auto const& left_chaining_value =
          this->_chaining_value_stack[--this->_stack_len];
      attribute_alignas std::array<uint8_t, k_block_len_bytes> parent_block;

      if consteval {
        std::span<uint8_t> const block_span{parent_block};
        for (size_t idx{}; idx < k_chaining_value_ints; ++idx) {
          store_word_le(
              block_span.subspan(k_bytes_per_word * idx, k_bytes_per_word),
              left_chaining_value[idx]);
          store_word_le(
              block_span.subspan(k_half_block_bytes + (k_bytes_per_word * idx),
                                 k_bytes_per_word),
              right_chaining_value[idx]);
        }
      } else {
        std::memcpy(parent_block.data(), left_chaining_value.data(),
                    k_half_block_bytes);
        std::memcpy(parent_block.data() + k_half_block_bytes,
                    right_chaining_value.data(), k_half_block_bytes);
      }

      compress_block<true>(this->_key, parent_block, 0U, Flags::FLAG_PARENT,
                           compress_scratch);

      if consteval {
        std::copy_n(compress_scratch.begin(), k_chaining_value_ints,
                    right_chaining_value.begin());
      } else {
        std::memcpy(right_chaining_value.data(), compress_scratch.data(),
                    k_chaining_value_ints);
      }

      current_chunks >>= 1U;
    }

    this->_chaining_value_stack[this->_stack_len++] = right_chaining_value;
    this->_total_chunks_count++;
    // NOLINTEND(cppcoreguidelines-pro-bounds-constant-array-index,
    // cppcoreguidelines-pro-bounds-pointer-arithmetic)
  }

 public:
  constexpr hasher_t()
      : _key{k_initial_vector},
        _chunk_state(k_initial_vector, 0U, Flags::FLAG_CHUNK_INIT) {}

  // Generic update accepting any ByteContiguousRange
  template <ByteContiguousRange Range>
  constexpr void update(Range const& input_data) noexcept {
    size_t taken_bytes{};
    auto const* data_ptr = std::ranges::data(input_data);
    size_t remaining_len = std::ranges::size(input_data);

    while (remaining_len > 0) {
      if (this->_chunk_state.total_len() == k_chunk_len_bytes) {
        auto const chunk_chaining_value =
            this->_chunk_state.output_chaining_value();
        push_stack(chunk_chaining_value);
        this->_chunk_state = chunk_state_t(
            this->_key, this->_total_chunks_count + 1U, Flags::FLAG_CHUNK_INIT);
      }

      size_t const needed = k_chunk_len_bytes - this->_chunk_state.total_len();
      size_t const can_take = (needed < remaining_len) ? needed : remaining_len;

      // Create a span subview for the specific chunk
      // We rely on std::span deduction guide to handle the ptr + len
      std::span const chunk_view(data_ptr + taken_bytes, can_take);

      this->_chunk_state.update(chunk_view);

      taken_bytes += can_take;
      remaining_len -= can_take;
    }
  }

  // NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables,
  // cppcoreguidelines-pro-bounds-constant-array-index)
  [[nodiscard]] constexpr auto finalize() const noexcept -> output_t {
    // 1. Handle Empty/Root-only case
    if (this->_total_chunks_count == 0UL) {
      auto const props = this->_chunk_state.get_root_props();
      return {props.chaining_values, props.block, props.flags};
    }

    // Prepare the common buffers
    attribute_alignas std::array<uint8_t, k_block_len_bytes> parent_block;

    // OPTIMIZATION: Reusable scratch buffer.
    attribute_alignas std::array<uint32_t, k_block_words_count>
        compress_scratch;

    // Initialize the "Right Child" directly into the parent block (Bytes
    // 32-63) We extract the chaining value from the current chunk state.
    auto const current_output = this->_chunk_state.output_chaining_value();

    if consteval {
      // Direct write to the second half of the block
      std::span<uint8_t> block_span{parent_block};
      for (size_t idx{}; idx < k_chaining_value_ints; ++idx) {
        store_word_le(
            block_span.subspan(k_half_block_bytes + (k_bytes_per_word * idx),
                               k_bytes_per_word),
            current_output[idx]);
      }
    } else {
      std::memcpy(parent_block.data() + k_half_block_bytes,
                  current_output.data(), k_half_block_bytes);
    }

    // Reduce the Stack
    size_t current_stack_idx = this->_stack_len;

    while (current_stack_idx > 0) {
      // A. Pop the "Left Child" from the stack
      auto const& left_chaining_value =
          this->_chaining_value_stack[--current_stack_idx];

      // B. Copy Left Child into parent_block (Bytes 0-31)
      if consteval {
        std::span<uint8_t> block_span{parent_block};
        for (size_t idx{}; idx < k_chaining_value_ints; ++idx) {
          store_word_le(
              block_span.subspan(k_bytes_per_word * idx, k_bytes_per_word),
              left_chaining_value[idx]);
        }
      } else {
        std::memcpy(parent_block.data(), left_chaining_value.data(),
                    k_half_block_bytes);
      }

      // Check if we are done
      // If we just popped the last item, 'parent_block' now contains
      // [Left Child | Right Child]. This is exactly what the Root Output needs.
      // We break BEFORE compressing, because output_t handles the final
      // compression.
      if (current_stack_idx == 0UL) {
        break;
      }

      // Compress the Parent
      // This produces a new chaining value for the next level up.
      compress_block<true>(this->_key, parent_block, 0UL, Flags::FLAG_PARENT,
                           compress_scratch);

      // Update the "Right Child" for the next iteration (Bytes 32-63)
      // OPTIMIZATION: Write directly from scratch to parent_block right half.
      if consteval {
        std::span<uint8_t> block_span{parent_block};
        for (size_t idx{}; idx < k_chaining_value_ints; ++idx) {
          store_word_le(
              block_span.subspan(k_half_block_bytes + (k_bytes_per_word * idx),
                                 k_bytes_per_word),
              compress_scratch[idx]);
        }
      } else {
        std::memcpy(parent_block.data() + k_half_block_bytes,
                    compress_scratch.data(), k_half_block_bytes);
      }
    }

    return {this->_key, parent_block, Flags::FLAG_PARENT};
  }
};
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables,
// cppcoreguidelines-pro-bounds-constant-array-index)

}  // namespace detail

constexpr auto hash_default_size = 32UL;

// 1. Compile-time constant size (Templated input)
template <size_t OutPutSize = hash_default_size,
          detail::ByteContiguousRange Range>
constexpr auto hash(Range const& input) noexcept
    -> std::array<uint8_t, OutPutSize> {
  detail::hasher_t hasher_obj;
  hasher_obj.update(input);
  return hasher_obj.finalize().template extract_array<OutPutSize>();
}

// 2. Runtime variable size (Templated input)
template <detail::ByteContiguousRange Range>
inline auto hash(Range const& input, size_t const num_bytes) noexcept
    -> std::vector<uint8_t> {
  detail::hasher_t hasher_obj;
  hasher_obj.update(input);

  std::vector<uint8_t> output_buffer(num_bytes, uint8_t{});
  hasher_obj.finalize().fill_destination(output_buffer);
  return output_buffer;
}

}  // namespace blake3
