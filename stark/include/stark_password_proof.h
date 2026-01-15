/**
 * STARK Password Proof Library - C Header
 * 
 * Zero-knowledge proof library for password authentication using STARK proofs.
 * 
 * This header provides C-compatible bindings to the Rust library.
 * 
 * Basic Usage:
 * 1. During registration: call c_get_commitment() and store the result
 * 2. During authentication: call c_prove_password() to generate a proof
 * 3. To verify: call c_verify_password_proof() with proof and stored commitment
 * 4. Always call c_free_proof() to release proof handles
 */

#ifndef STARK_PASSWORD_PROOF_H
#define STARK_PASSWORD_PROOF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Error codes returned by library functions.
 */
typedef enum {
    STARK_SUCCESS = 0,
    STARK_ERROR_INVALID_PASSWORD = 1,
    STARK_ERROR_INVALID_SALT = 2,
    STARK_ERROR_INVALID_ARGON_PARAMS = 3,
    STARK_ERROR_ARGON_ERROR = 4,
    STARK_ERROR_PROVING_ERROR = 5,
    STARK_ERROR_VERIFICATION_ERROR = 6,
    STARK_ERROR_SERIALIZATION_ERROR = 7,
    STARK_ERROR_INVALID_PROOF_FORMAT = 8,
    STARK_ERROR_COMMITMENT_MISMATCH = 9,
    STARK_ERROR_INVALID_HANDLE = 10,
    STARK_ERROR_INTERNAL_PANIC = 11
} StarkErrorCode;

/**
 * Opaque handle for proof results.
 * Must be freed with c_free_proof().
 */
typedef struct OpaqueProofResult OpaqueProofResult;

/**
 * Result of commitment computation.
 */
typedef struct {
    uint64_t values[4];  /**< Commitment values (4 field elements) */
    bool success;        /**< true if computation succeeded */
} CommitmentResult;

/* ============================================================================
 * Input Limits (for validation)
 * ============================================================================ */

#define STARK_MAX_PASSWORD_LEN 128  /**< Maximum password length in bytes */
#define STARK_MIN_SALT_LEN 8        /**< Minimum salt length in bytes */
#define STARK_MAX_SALT_LEN 64       /**< Maximum salt length in bytes */
#define STARK_MIN_M_COST 8          /**< Minimum Argon2 memory cost (KB) */
#define STARK_MAX_M_COST 65536      /**< Maximum Argon2 memory cost (KB) */
#define STARK_MAX_T_COST 10         /**< Maximum Argon2 time cost */
#define STARK_MAX_P_COST 4          /**< Maximum Argon2 parallelism */

/* ============================================================================
 * Core Functions
 * ============================================================================ */

/**
 * Derives a secret field element from password using Argon2id.
 * 
 * @param password_ptr   Pointer to password bytes (UTF-8)
 * @param password_len   Length of password in bytes
 * @param salt_ptr       Pointer to salt bytes
 * @param salt_len       Length of salt in bytes (8-64)
 * @param m_cost         Argon2 memory cost in KB (8-65536)
 * @param t_cost         Argon2 time cost / iterations (1-10)
 * @param p_cost         Argon2 parallelism degree (1-4)
 * 
 * @return Derived secret as uint64, or 0 on error
 */
uint64_t c_derive_secret_start(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* salt_ptr, size_t salt_len,
    uint32_t m_cost, uint32_t t_cost, uint32_t p_cost
);

/**
 * Computes commitment hash for a password.
 * Store this during registration for later verification.
 * 
 * @param password_ptr   Pointer to password bytes (UTF-8)
 * @param password_len   Length of password in bytes
 * @param salt_ptr       Pointer to salt bytes
 * @param salt_len       Length of salt in bytes (8-64)
 * @param m_cost         Argon2 memory cost in KB
 * @param t_cost         Argon2 time cost
 * @param p_cost         Argon2 parallelism
 * 
 * @return CommitmentResult with success=true if computation succeeded
 */
CommitmentResult c_get_commitment(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* salt_ptr, size_t salt_len,
    uint32_t m_cost, uint32_t t_cost, uint32_t p_cost
);

/**
 * Generates a STARK proof of password knowledge.
 * 
 * @param password_ptr   Pointer to password bytes (UTF-8)
 * @param password_len   Length of password in bytes
 * @param salt_ptr       Pointer to salt bytes
 * @param salt_len       Length of salt in bytes
 * @param m_cost         Argon2 memory cost in KB
 * @param t_cost         Argon2 time cost
 * @param p_cost         Argon2 parallelism
 * 
 * @return Opaque handle to proof, or NULL on error.
 *         Must be freed with c_free_proof().
 */
OpaqueProofResult* c_prove_password(
    const uint8_t* password_ptr, size_t password_len,
    const uint8_t* salt_ptr, size_t salt_len,
    uint32_t m_cost, uint32_t t_cost, uint32_t p_cost
);

/**
 * Gets the status code from a proof handle.
 * 
 * @param proof_ptr   Proof handle from c_prove_password
 * 
 * @return Status code (STARK_SUCCESS=0 if valid)
 */
uint32_t c_get_proof_status(const OpaqueProofResult* proof_ptr);

/**
 * Gets the proof data length in bytes.
 * 
 * @param proof_ptr   Proof handle from c_prove_password
 * 
 * @return Length in bytes, or 0 if handle is invalid
 */
size_t c_get_proof_len(const OpaqueProofResult* proof_ptr);

/**
 * Copies proof data to a buffer.
 * 
 * @param proof_ptr   Proof handle from c_prove_password
 * @param buffer      Destination buffer
 * @param buffer_len  Size of destination buffer
 * 
 * @return Number of bytes copied, or 0 on error
 */
size_t c_copy_proof_data(
    const OpaqueProofResult* proof_ptr,
    uint8_t* buffer,
    size_t buffer_len
);

/**
 * Verifies a STARK proof of password knowledge.
 * 
 * @param proof_ptr       Proof handle from c_prove_password
 * @param commitment_ptr  Pointer to 4 uint64 commitment values
 * 
 * @return true if proof is valid, false otherwise
 */
bool c_verify_password_proof(
    const OpaqueProofResult* proof_ptr,
    const uint64_t* commitment_ptr
);

/**
 * Frees a proof handle.
 * Safe to call with NULL.
 * 
 * @param proof_ptr   Proof handle to free
 */
void c_free_proof(OpaqueProofResult* proof_ptr);

#ifdef __cplusplus
}
#endif

#endif /* STARK_PASSWORD_PROOF_H */
