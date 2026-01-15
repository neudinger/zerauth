# STARK Password Proof Library

A zero-knowledge proof library for password authentication using STARK proofs. This library allows a prover to demonstrate knowledge of a password without revealing the password itself.

## Features

- **Zero-Knowledge**: Proves password knowledge without exposing the password
- **STARK-based**: Uses FRI polynomial commitment for post-quantum security assumptions
- **Argon2id**: Memory-hard password derivation resistant to GPU/ASIC attacks
- **FFI Support**: C-compatible interface for cross-language integration
- **Production-Ready**: Comprehensive input validation, error handling, and testing

## Security Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Field | Goldilocks | 64-bit prime: 2^64 - 2^32 + 1 |
| Hash | Poseidon2 | SP-network with x^7 S-box |
| Rounds | 255 | Exceeds 30 rounds for 128-bit security |
| Extension | Quadratic | 100+ bit security level |
| FRI Blowup | 8x | log_blowup=3 for degree-7 constraints |
| Key Derivation | Argon2id | Memory-hard, timing-resistant |

## Quick Start

### Rust API

```rust
use stark_password_proof::{get_commitment, prove_password, verify_password_proof};

// Registration: compute and store commitment
let password = "my_secret_password";
let salt = b"unique_user_salt"; // 8-64 bytes, unique per user
let commitment = get_commitment(password, salt, 4096, 3, 1)?;
// Store commitment in database

// Authentication: generate proof
let proof = prove_password(password, salt, 4096, 3, 1)?;
// Send proof to verifier

// Verification: check proof against stored commitment
let valid = verify_password_proof(&proof, commitment)?;
assert!(valid);
```

### C FFI API

```c
#include "stark_password_proof.h"

// Registration
CommitmentResult result = c_get_commitment(
    (uint8_t*)"password", 8,
    (uint8_t*)"saltsalt", 8,
    4096, 3, 1
);
if (result.success) {
    // Store result.values[4] in database
}

// Authentication
OpaqueProofResult* proof = c_prove_password(
    (uint8_t*)"password", 8,
    (uint8_t*)"saltsalt", 8,
    4096, 3, 1
);

if (proof && c_get_proof_status(proof) == STARK_SUCCESS) {
    // Verification
    bool valid = c_verify_password_proof(proof, stored_commitment);
}

// Always free the proof handle
c_free_proof(proof);
```

## Input Parameters

### Password Requirements
- Length: 1-128 bytes
- Encoding: Valid UTF-8

### Salt Requirements
- Length: 8-64 bytes
- **Important**: Use a unique, cryptographically random salt per user
- Store the salt alongside the commitment

### Argon2id Parameters

| Parameter | Range | Recommended | Description |
|-----------|-------|-------------|-------------|
| `m_cost` | 8-65536 | 4096-65536 | Memory in KB |
| `t_cost` | 1-10 | 3 | Number of iterations |
| `p_cost` | 1-4 | 1 | Parallelism degree |

Higher values increase security but also computation time. Recommended production settings:
- **Interactive login**: `m_cost=4096, t_cost=3, p_cost=1`
- **Sensitive operations**: `m_cost=65536, t_cost=4, p_cost=1`

## Building

### Prerequisites
- Rust 1.70+
- C compiler (for FFI usage)

### Build

```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Run tests
cargo test

# Check for issues
cargo clippy -- -D warnings
```

### Generate C Library

```bash
# Build as cdylib
cargo build --release

# The library will be at:
# - Linux: target/release/libstark_password_proof.so
# - macOS: target/release/libstark_password_proof.dylib  
# - Windows: target/release/stark_password_proof.dll
```

## Performance

Approximate timings on modern hardware (4-core CPU):

| Operation | Time |
|-----------|------|
| Key derivation (m=4096) | ~100ms |
| Proof generation | ~500ms |
| Proof verification | ~100ms |

Proof size: ~50-100 KB

## Error Handling

### Rust

All fallible functions return `Result<T, StarkError>`:

```rust
match prove_password(password, salt, m_cost, t_cost, p_cost) {
    Ok(proof) => { /* use proof */ }
    Err(e) => {
        eprintln!("Error {:?}: {}", e.code, e.message);
    }
}
```

### C FFI

Check return values and use status codes:

```c
OpaqueProofResult* proof = c_prove_password(...);
if (!proof) {
    fprintf(stderr, "Proof generation failed\n");
    return;
}

uint32_t status = c_get_proof_status(proof);
if (status != STARK_SUCCESS) {
    fprintf(stderr, "Error code: %u\n", status);
}

c_free_proof(proof);
```

## Security Considerations

### DO ✅

- Use unique, random salts per user (16+ bytes recommended)
- Store salts alongside commitments
- Use adequate Argon2 parameters for your threat model
- Keep salt and commitment secret from unauthorized parties

### DON'T ❌

- Reuse salts across users
- Use weak passwords (library can't enforce this)
- Skip input validation in wrapper code
- Ignore error codes

### Threat Model

**Protected Against**:
- Password exposure during authentication
- Replay attacks (proofs are bound to commitments)
- Timing side-channels on key derivation

**Not Protected Against**:
- Client-side credential theft (keyloggers, malware)
- Weak passwords (dictionary attacks on leaked commitments)
- Implementation bugs (use audited code in production)

## Development

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_prove_and_verify

# With output
cargo test -- --nocapture
```

### Debugging

```bash
# Enable debug output
RUST_BACKTRACE=1 cargo test

# Memory analysis (Linux)
valgrind --leak-check=full cargo test
```

## License

See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Plonky3](https://github.com/Plonky3/Plonky3) - STARK proving system
- [argon2](https://crates.io/crates/argon2) - Key derivation
- [Horizen Labs](https://www.horizen.io/) - Poseidon2 constants

## Security Audit Notice

⚠️ **This library has not undergone a security audit.** Use in production at your own risk. For high-security applications, a professional cryptographic audit is strongly recommended.
