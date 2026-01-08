#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function declarations from the Rust library
uint64_t c_derive_secret_start(const char* password, uint64_t salt);
uint64_t c_get_commitment(const char* password, uint64_t salt);
uint8_t* c_prove_password(const char* password, uint64_t salt, uint64_t nonce,
                          size_t* out_len);
int c_verify_password_proof(const uint8_t* proof_ptr, size_t proof_len,
                            uint64_t expected_commitment, uint64_t nonce);
void c_free_proof(uint8_t* ptr, size_t len);

int main() {
  const char* password = "correct_horse_battery_staple";
  uint64_t salt = 123456789;
  uint64_t nonce = 0;

  printf("1. Testing c_derive_secret_start...\n");
  uint64_t start_val = c_derive_secret_start(password, salt);
  printf("Start value: %lu\n", start_val);

  printf("2. Testing c_get_commitment...\n");
  uint64_t commitment = c_get_commitment(password, salt);
  printf("Commitment: %lu\n", commitment);

  printf("3. Testing c_prove_password...\n");
  size_t proof_len = 0;
  uint8_t* proof = c_prove_password(password, salt, nonce, &proof_len);
  printf("Proof generated. Length: %zu\n", proof_len);

  if (proof == NULL || proof_len == 0) {
    printf("FAILED: Proof generation returned NULL or empty\n");
    return 1;
  }

  printf("4. Testing c_verify_password_proof (Valid)...\n");
  int valid = c_verify_password_proof(proof, proof_len, commitment, nonce);
  if (valid) {
    printf("SUCCESS: Proof verified correctly.\n");
  } else {
    printf("FAILED: Valid proof failed to verify.\n");
    return 1;
  }

  printf("5. Testing c_verify_password_proof (Invalid Commitment)...\n");
  int invalid_commit =
      c_verify_password_proof(proof, proof_len, commitment + 1, nonce);
  if (!invalid_commit) {
    printf("SUCCESS: Invalid commitment rejected.\n");
  } else {
    printf("FAILED: Invalid commitment was accepted.\n");
    return 1;
  }

  printf("6. Testing c_verify_password_proof (Invalid Nonce)...\n");
  int invalid_nonce =
      c_verify_password_proof(proof, proof_len, commitment, nonce + 1);
  if (!invalid_nonce) {
    printf("SUCCESS: Invalid nonce rejected.\n");
  } else {
    printf("FAILED: Invalid nonce was accepted.\n");
    return 1;
  }

  printf("7. Testing c_free_proof...\n");
  c_free_proof(proof, proof_len);
  printf("Memory freed.\n");

  printf("ALL TESTS PASSED.\n");
  return 0;
}
