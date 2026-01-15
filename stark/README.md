# STARK Password Proof System

## ⚠️ **CRITICAL WARNING: NOT PRODUCTION READY**

**DO NOT USE THIS CODE IN PRODUCTION SYSTEMS**

This is an **educational prototype** demonstrating STARK-based password authentication architecture. It contains critical security vulnerabilities that make it completely insecure for real-world use.

🔴 **See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for detailed vulnerability analysis**

---

## Overview

This repository demonstrates a Zero-Knowledge STARK proof system for password authentication using the Plonky3 framework. The system allows a user to prove knowledge of a password without revealing it or any intermediate values.

### Architecture

```
┌──────────┐
│ Password │
└────┬─────┘
     │ Argon2 (password hardening)
     ▼
 [Secret]  ←─── Private Witness
     │
     │ Hash Function (Poseidon-variant)
     ▼
[Commitment] ←─── Public (stored in database)
     │
     │ STARK Proof
     ▼
[Verified] ✓
```

## What This Demonstrates

✅ **Correct architectural patterns** for ZK password authentication  
✅ **Plonky3 API usage** (AIR, PCS, FRI, Merkle Trees)  
✅ **SP-Network design** (Substitution-Permutation Network)  
✅ **Constraint optimization** (helper columns for degree reduction)  
✅ **FFI safety** (panic catching, memory management)  

❌ **NOT cryptographically secure** (uses placeholder constants)  
❌ **NOT production ready** (multiple critical vulnerabilities)  
❌ **NOT audited** (proof-of-concept only)

## Critical Vulnerabilities

1. **Placeholder cryptographic constants** - MDS matrix and round constants are not secure
2. **Non-standard hash** - Missing partial rounds, unaudited construction  
3. **Manual hasher implementations** - Fragile and potentially incorrect
4. **Runtime RNG for constants** - Should use hardcoded values

**Initial state attack** was present but has been FIXED with first-row constraints.

See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for complete details.

## Building

```bash
cd stark
cargo build --release
cargo test
```

**Note**: Tests currently fail due to FRI dimension mismatch (work in progress).

## Code Structure

```
stark/
├── src/
│   └── lib.rs          # Main implementation
├── SECURITY_AUDIT.md   # Complete vulnerability analysis  
├── SECURITY.md         # Architecture documentation
└── Cargo.toml
```

### Key Components

- **AIR Definition** (Lines 38-148): Poseidon-variant hash constraints
  - S-Box: x^7 (computed efficiently as x * x² * x⁴)
  - Linear Layer: MDS matrix multiplication
  - Boundary constraints: First row (initial state) and last row (output)

- **Trace Generation** (Lines 554-610): Computes hash rounds

- **FFI Interface** (Lines 800+): C-compatible API with panic safety

## Educational Use Cases

✓ Learning ZK-STARK proof systems  
✓ Understanding Plonky3 framework  
✓ Prototyping custom AIRs  
✓ Academic research  

✗ Production password authentication  
✗ Security-critical applications  
✗ Cryptocurrency/blockchain systems  

## Production Requirements

To make this production-ready would require:

1. **Replace all cryptographic constants** with official Poseidon values
2. **Implement standard Poseidon** (or use `p3_poseidon2` directly)
3. **Remove manual hasher implementations**
4. **Professional cryptographic audit**
5. **Extensive testing and fuzzing**
6. **Formal verification** of constraints

**Estimated effort**: 3-6 months with cryptography expertise

## Dependencies

- `plonky3` (v0.4.2) - STARK proof system
- `argon2` - Password hashing (off-chain)
- `rand`, `serde`, `postcard` - Utilities

## License

MIT License (see LICENSE file)

**DISCLAIMER**: This code is provided "AS IS" for educational purposes only. The authors accept NO responsibility for security vulnerabilities or damages resulting from use in production systems.

## References

- [Poseidon Hash Function](https://eprint.iacr.org/2019/458.pdf)
- [Plonky3 Documentation](https://github.com/Plonky3/Plonky3)
- [STARK Protocol Overview](https://vitalik.ca/general/2017/11/09/starks_part_1.html)

## Contributing

This is an educational project. Contributions that improve the educational value are welcome, but remember this is NOT intended for production use.

Issues demonstrating new attack vectors or educational improvements are appreciated!

---

**Status**: 🔴 Educational Prototype  
**Security**: ⚠️ Multiple Critical Vulnerabilities  
**Production Ready**: ❌ NO  
**Last Updated**: 2026-01-15
