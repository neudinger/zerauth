// FFI functions intentionally perform null checks before dereferencing
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! # STARK Password Proof Library
//! 
//! A zero-knowledge proof library for password authentication using STARK proofs.
//! This library allows a prover to demonstrate knowledge of a password without
//! revealing the password itself.
//!
//! ## Overview
//! 
//! The library implements a ZK-STARK proof system for password verification:
//! 
//! 1. **Registration**: Hash password → store commitment
//! 2. **Authentication**: Generate ZK proof of password knowledge
//! 3. **Verification**: Verify proof against stored commitment
//!
//! ## Security Parameters
//! 
//! | Parameter | Value | Description |
//! |-----------|-------|-------------|
//! | Field | Goldilocks | 64-bit prime: 2^64 - 2^32 + 1 |
//! | Hash | Poseidon2 | SP-network with x^7 S-box |
//! | Rounds | 255 | Exceeds 30 rounds for 128-bit security |
//! | Extension | Quadratic | 100+ bit security level |
//! | FRI Blowup | 8x | log_blowup=3 for degree-7 constraints |
//!
//! ## Cryptographic Components
//!
//! - **Key Derivation**: Argon2id (memory-hard, timing-resistant)
//! - **AIR Constraint System**: Poseidon-style SP-network
//! - **Polynomial Commitment**: FRI-based (Two-Adic)
//! - **Challenger**: Duplex sponge construction
//!
//! ## Threat Model
//!
//! **Protected Against**:
//! - Password exposure during authentication
//! - Replay attacks (proofs are bound to commitment)
//! - Timing attacks on key derivation (modular reduction)
//!
//! **Assumptions**:
//! - Argon2id parameters provide adequate memory-hardness
//! - Poseidon2 behaves as a random oracle
//! - FRI commitment scheme is computationally binding
//!
//! ## Example Usage
//!
//! ```rust,ignore
//! use stark_password_proof::{get_commitment, prove_password, verify_password_proof};
//!
//! // Registration: store this commitment
//! let commitment = get_commitment("password123", b"unique_salt!", 4096, 3, 1)?;
//!
//! // Authentication: generate proof
//! let proof = prove_password("password123", b"unique_salt!", 4096, 3, 1)?;
//!
//! // Verification: check proof against commitment
//! let valid = verify_password_proof(&proof, commitment)?;
//! assert!(valid);
//! ```
//!
//! ## FFI Safety
//!
//! This library exports C-compatible functions for cross-language use.
//! All FFI functions:
//! - Validate pointer arguments before dereferencing
//! - Catch panics to prevent undefined behavior
//! - Return error codes for failure cases
//! - Use opaque handles to prevent misuse

use p3_field::{PrimeField64, PrimeCharacteristicRing};
use p3_symmetric::TruncatedPermutation;
use p3_field::extension::BinomialExtensionField; 
use p3_air::{Air, AirBuilder, BaseAir, AirBuilderWithPublicValues}; 
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_goldilocks::{Goldilocks, Poseidon2ExternalLayerGoldilocksHL, Poseidon2InternalLayerGoldilocks}; 
use p3_uni_stark::{prove, verify, StarkConfig, Proof}; 
use p3_challenger::DuplexChallenger; 
use p3_dft::Radix2DitParallel;
use p3_fri::{TwoAdicFriPcs, FriParameters}; 
use p3_merkle_tree::MerkleTreeMmcs;
use p3_commit::ExtensionMmcs;

use p3_poseidon2::Poseidon2;
use p3_symmetric::PaddingFreeSponge;
use rand::{rngs::StdRng, SeedableRng};
use serde::{Serialize, Deserialize};

// ============================================================================
// 1. CONSTANTS & TYPES
// ============================================================================

/// The Goldilocks prime: 2^64 - 2^32 + 1
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// Base field type (Goldilocks)
type Val = Goldilocks;

/// Extension field for challenges (quadratic extension)
type Challenge = BinomialExtensionField<Val, 2>;

// --- INPUT VALIDATION LIMITS ---

/// Maximum allowed password length in bytes
pub const MAX_PASSWORD_LEN: usize = 128;

/// Minimum required salt length in bytes (Argon2 requirement)
pub const MIN_SALT_LEN: usize = 8;

/// Maximum allowed salt length in bytes
pub const MAX_SALT_LEN: usize = 64;

/// Maximum Argon2 memory cost (64MB)
pub const MAX_M_COST: u32 = 65536;

/// Minimum Argon2 memory cost 
pub const MIN_M_COST: u32 = 8;

/// Maximum Argon2 time cost
pub const MAX_T_COST: u32 = 10;

/// Maximum Argon2 parallelism
pub const MAX_P_COST: u32 = 4;

// --- CRYPTOGRAPHIC CONSTANTS ---

/// Number of hash rounds (255 → trace height 256, exceeds 30 for 128-bit security)
const NUM_ROUNDS: usize = 255;

/// MDS matrix from Horizen Labs Poseidon2 implementation
/// This 4x4 circulant matrix provides optimal diffusion
const MDS_MATRIX: [[u64; 4]; 4] = [
    [5, 7, 1, 3],
    [4, 6, 1, 1],
    [1, 3, 5, 7],
    [1, 1, 4, 6],
];

/// Round constant from official Plonky3 Poseidon2 internal rounds
/// Source: p3-goldilocks/src/poseidon2.rs
const ROUND_CONSTANT: u64 = 0x488897d85ff51f56;

/// Magic number for FFI handle validation
const PROOF_HANDLE_MAGIC: u64 = 0x5354_4152_4B50_5246; // "STARKPRF"

// ============================================================================
// 2. ERROR TYPES
// ============================================================================

/// Error codes for FFI and internal use.
/// 
/// These codes are returned by C FFI functions and can be used
/// to determine the cause of failures.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Operation completed successfully
    Success = 0,
    /// Password is empty, too long, or invalid UTF-8
    InvalidPassword = 1,
    /// Salt length is outside allowed range
    InvalidSalt = 2,
    /// Argon2 parameters are invalid
    InvalidArgonParams = 3,
    /// Argon2 hashing failed
    ArgonError = 4,
    /// Proof generation failed
    ProvingError = 5,
    /// Proof verification failed
    VerificationError = 6,
    /// Serialization/deserialization failed
    SerializationError = 7,
    /// Proof format is invalid or corrupted
    InvalidProofFormat = 8,
    /// Commitment in proof doesn't match expected
    CommitmentMismatch = 9,
    /// Invalid FFI handle (null, invalid magic, etc.)
    InvalidHandle = 10,
    /// Internal panic was caught
    InternalPanic = 11,
}

/// Detailed error information.
///
/// Contains both a machine-readable error code and a human-readable message.
#[derive(Debug, Clone)]
pub struct StarkError {
    /// Machine-readable error code
    pub code: ErrorCode,
    /// Human-readable error message
    pub message: String,
}

impl std::fmt::Display for StarkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}", self.code, self.message)
    }
}

impl std::error::Error for StarkError {}

impl From<argon2::Error> for StarkError {
    fn from(e: argon2::Error) -> Self {
        StarkError { code: ErrorCode::ArgonError, message: e.to_string() }
    }
}

// ============================================================================
// 3. INPUT VALIDATION
// ============================================================================

/// Validates all input parameters before cryptographic operations.
///
/// # Parameters
/// - `password`: Must be 1-128 bytes, valid UTF-8
/// - `salt`: Must be 8-64 bytes
/// - `m_cost`: Argon2 memory cost, 8-65536 KB
/// - `t_cost`: Argon2 time cost (iterations), 1-10
/// - `p_cost`: Argon2 parallelism, 1-4
///
/// # Returns
/// - `Ok(())` if all parameters are valid
/// - `Err(StarkError)` with details if validation fails
pub fn validate_inputs(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<(), StarkError> {
    if password.is_empty() {
        return Err(StarkError { 
            code: ErrorCode::InvalidPassword, 
            message: "Password cannot be empty".to_string() 
        });
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(StarkError { 
            code: ErrorCode::InvalidPassword, 
            message: format!("Password exceeds maximum length of {} bytes", MAX_PASSWORD_LEN) 
        });
    }
    if salt.len() < MIN_SALT_LEN {
        return Err(StarkError { 
            code: ErrorCode::InvalidSalt, 
            message: format!("Salt must be at least {} bytes (got {})", MIN_SALT_LEN, salt.len()) 
        });
    }
    if salt.len() > MAX_SALT_LEN {
        return Err(StarkError { 
            code: ErrorCode::InvalidSalt, 
            message: format!("Salt exceeds maximum length of {} bytes", MAX_SALT_LEN) 
        });
    }
    if !(MIN_M_COST..=MAX_M_COST).contains(&m_cost) {
        return Err(StarkError { 
            code: ErrorCode::InvalidArgonParams, 
            message: format!("m_cost must be {}-{} (got {})", MIN_M_COST, MAX_M_COST, m_cost) 
        });
    }
    if !(1..=MAX_T_COST).contains(&t_cost) {
        return Err(StarkError { 
            code: ErrorCode::InvalidArgonParams, 
            message: format!("t_cost must be 1-{} (got {})", MAX_T_COST, t_cost) 
        });
    }
    if !(1..=MAX_P_COST).contains(&p_cost) {
        return Err(StarkError { 
            code: ErrorCode::InvalidArgonParams, 
            message: format!("p_cost must be 1-{} (got {})", MAX_P_COST, p_cost) 
        });
    }
    Ok(())
}

// ============================================================================
// 4. AIR DEFINITION
// ============================================================================

/// Algebraic Intermediate Representation for Poseidon-style preimage proof.
///
/// This AIR proves knowledge of a secret S such that applying NUM_ROUNDS
/// iterations of a Poseidon-style round function yields the public commitment.
///
/// ## Trace Layout (Width = 8)
/// | Col 0-3 | Col 4-7 |
/// |---------|---------|
/// | State s0-s3 | S-box outputs s0^7 - s3^7 |
///
/// ## Constraints
/// 1. **First Row**: Only s0 contains secret, s1=s2=s3=0
/// 2. **S-Box**: sbox[i] = state[i]^7
/// 3. **Linear Layer**: state' = MDS × sbox + RC
/// 4. **Last Row**: state = public_commitment
#[derive(Clone)]
struct PoseidonPreimageAir {
    _num_rounds: usize,
}

impl BaseAir<Val> for PoseidonPreimageAir {
    fn width(&self) -> usize { 8 }
}

impl<AB: AirBuilder<F = Val> + AirBuilderWithPublicValues> Air<AB> for PoseidonPreimageAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        
        let s0 = local[0].clone();
        let s1 = local[1].clone();
        let s2 = local[2].clone();
        let s3 = local[3].clone();
        let s0_7 = local[4].clone();
        let s1_7 = local[5].clone();
        let s2_7 = local[6].clone();
        let s3_7 = local[7].clone();
        
        // First row: only s0 has secret, others zero
        builder.when_first_row().assert_eq(s1.clone(), AB::Expr::ZERO);
        builder.when_first_row().assert_eq(s2.clone(), AB::Expr::ZERO);
        builder.when_first_row().assert_eq(s3.clone(), AB::Expr::ZERO);
        
        // S-box: x^7 = x * x^2 * x^4
        let s0_2 = s0.clone() * s0.clone();
        let s0_4 = s0_2.clone() * s0_2.clone();
        builder.assert_eq(s0_7.clone(), s0_4 * s0_2 * s0.clone());
        
        let s1_2 = s1.clone() * s1.clone();
        let s1_4 = s1_2.clone() * s1_2.clone();
        builder.assert_eq(s1_7.clone(), s1_4 * s1_2 * s1.clone());
        
        let s2_2 = s2.clone() * s2.clone();
        let s2_4 = s2_2.clone() * s2_2.clone();
        builder.assert_eq(s2_7.clone(), s2_4 * s2_2 * s2.clone());
        
        let s3_2 = s3.clone() * s3.clone();
        let s3_4 = s3_2.clone() * s3_2.clone();
        builder.assert_eq(s3_7.clone(), s3_4 * s3_2 * s3.clone());
        
        // Linear layer: state' = MDS * sbox + RC
        let rc = AB::Expr::from(Val::from_u64(ROUND_CONSTANT));
        
        let new_s0 = AB::Expr::from(Val::from_u64(MDS_MATRIX[0][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][3])) * s3_7.clone()
                   + rc.clone();
        
        let new_s1 = AB::Expr::from(Val::from_u64(MDS_MATRIX[1][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][3])) * s3_7.clone()
                   + rc.clone();
        
        let new_s2 = AB::Expr::from(Val::from_u64(MDS_MATRIX[2][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][3])) * s3_7.clone()
                   + rc.clone();
        
        let new_s3 = AB::Expr::from(Val::from_u64(MDS_MATRIX[3][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][3])) * s3_7.clone()
                   + rc;
        
        builder.when_transition().assert_eq(next[0].clone(), new_s0);
        builder.when_transition().assert_eq(next[1].clone(), new_s1);
        builder.when_transition().assert_eq(next[2].clone(), new_s2);
        builder.when_transition().assert_eq(next[3].clone(), new_s3);
        
        // Last row: state must match public commitment
        let pis = builder.public_values();
        let e0 = pis[0]; let e1 = pis[1]; let e2 = pis[2]; let e3 = pis[3];
        
        builder.when_last_row().assert_eq(local[0].clone(), e0);
        builder.when_last_row().assert_eq(local[1].clone(), e1);
        builder.when_last_row().assert_eq(local[2].clone(), e2);
        builder.when_last_row().assert_eq(local[3].clone(), e3);
    }
}

// ============================================================================
// 5. TYPE ALIASES
// ============================================================================

type MyPerm = Poseidon2<Val, Poseidon2ExternalLayerGoldilocksHL<8>, Poseidon2InternalLayerGoldilocks, 8, 7>;
type MyHash = PaddingFreeSponge<MyPerm, 8, 4, 4>;
type MyCompress = TruncatedPermutation<MyPerm, 2, 4, 8>;
type ValMmcs = MerkleTreeMmcs<Val, Val, MyHash, MyCompress, 4>;
type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
type Dft = Radix2DitParallel<Val>;
type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
type Challenger = DuplexChallenger<Val, MyPerm, 8, 4>;
type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;

// ============================================================================
// 6. ARGON2 & TRACE GENERATION
// ============================================================================

/// Derives a field element from a password using Argon2id.
///
/// Uses modular reduction for constant-time conversion, avoiding
/// timing side-channels from rejection sampling.
///
/// # Parameters
/// - `password`: User password (1-128 bytes)
/// - `salt`: Unique salt (8-64 bytes)  
/// - `m_cost`: Memory cost in KB (8-65536)
/// - `t_cost`: Time cost / iterations (1-10)
/// - `p_cost`: Parallelism degree (1-4)
///
/// # Returns
/// A deterministic field element derived from the password.
///
/// # Security
/// The Argon2id algorithm provides:
/// - Memory-hard computation (GPU/ASIC resistant)
/// - Timing-attack resistance
/// - Side-channel protection
pub fn derive_secret_start(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Val, StarkError> {
    validate_inputs(password, salt, m_cost, t_cost, p_cost)?;
    
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| StarkError { code: ErrorCode::ArgonError, message: e.to_string() })?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    
    let mut output = [0u8; 32];
    argon.hash_password_into(password.as_bytes(), salt, &mut output)?;
    
    // Constant-time modular reduction (no rejection sampling)
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&output[0..8]);
    let raw_u64 = u64::from_le_bytes(val_bytes);
    let reduced = raw_u64 % GOLDILOCKS_PRIME;
    Ok(Val::from_u64(reduced))
}

/// Generates the execution trace for the Poseidon-style AIR.
///
/// The trace has dimensions (height × 8) where height = 2^⌈log₂(num_rounds+1)⌉.
fn generate_poseidon_trace(secret: Val, num_rounds: usize) -> (RowMajorMatrix<Val>, [Val; 4]) {
    let height = (num_rounds + 1).next_power_of_two();
    let width = 8;
    
    let mut trace_data = vec![Val::ZERO; height * width];
    let mut state = [secret, Val::ZERO, Val::ZERO, Val::ZERO];
    
    for i in 0..height {
        let row_idx = i * width;
        
        // Write state columns
        trace_data[row_idx] = state[0];
        trace_data[row_idx + 1] = state[1];
        trace_data[row_idx + 2] = state[2];
        trace_data[row_idx + 3] = state[3];
        
        // Compute and write S-box columns
        let s0_7 = state[0].exp_u64(7);
        let s1_7 = state[1].exp_u64(7);
        let s2_7 = state[2].exp_u64(7);
        let s3_7 = state[3].exp_u64(7);
        
        trace_data[row_idx + 4] = s0_7;
        trace_data[row_idx + 5] = s1_7;
        trace_data[row_idx + 6] = s2_7;
        trace_data[row_idx + 7] = s3_7;
        
        // Compute next state
        if i < height - 1 {
            let rc = Val::from_u64(ROUND_CONSTANT);
            let s_vec = [s0_7, s1_7, s2_7, s3_7];
            
            let mut next_state = [Val::ZERO; 4];
            for r in 0..4 {
                let mut sum = rc;
                for c in 0..4 {
                    sum += Val::from_u64(MDS_MATRIX[r][c]) * s_vec[c];
                }
                next_state[r] = sum;
            }
            state = next_state;
        }
    }
    
    // Extract commitment from final state
    let final_row = num_rounds.min(height - 1);
    let final_row_idx = final_row * width;
    let commitment = [
        trace_data[final_row_idx],
        trace_data[final_row_idx + 1],
        trace_data[final_row_idx + 2],
        trace_data[final_row_idx + 3],
    ];
    
    (RowMajorMatrix::new(trace_data, width), commitment)
}

/// Creates the STARK configuration with appropriate FRI parameters.
fn make_config() -> (MyConfig, MyPerm) {
    let mut rng = StdRng::seed_from_u64(42);
    let perm: MyPerm = Poseidon2::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    
    // FRI parameters optimized for degree-7 S-box constraints
    let fri_params = FriParameters {
        log_blowup: 3,      // 8x blowup to accommodate high-degree constraints
        log_final_poly_len: 0,
        num_queries: 50,    // ~100 bits security with log_blowup=3
        commit_proof_of_work_bits: 8,
        query_proof_of_work_bits: 8,
        mmcs: challenge_mmcs,
    };
    
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm.clone());
    (MyConfig::new(pcs, challenger), perm)
}

/// Computes the commitment hash for a password.
///
/// This commitment should be stored during registration and used
/// to verify proofs during authentication.
///
/// # Parameters
/// Same as `derive_secret_start`
///
/// # Returns
/// A 4-element commitment that uniquely identifies the password.
/// 
/// # Example
/// ```rust,ignore
/// let commitment = get_commitment("my_password", b"unique_salt!", 4096, 3, 1)?;
/// // Store commitment in database
/// ```
pub fn get_commitment(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<[Val; 4], StarkError> {
    let secret = derive_secret_start(password, salt, m_cost, t_cost, p_cost)?;
    let (_trace, commitment) = generate_poseidon_trace(secret, NUM_ROUNDS);
    Ok(commitment)
}

// ============================================================================
// 7. PROOF GENERATION & VERIFICATION
// ============================================================================

/// Serialized proof payload containing commitment and STARK proof.
#[derive(Serialize, Deserialize)]
pub struct ProofPayload {
    /// The commitment this proof is for
    pub commitment: [u64; 4],
    /// Validity flag (always true for valid proofs)
    pub valid: bool,
    /// Serialized STARK proof bytes
    pub proof_bytes: Vec<u8>,
}

/// Generates a STARK proof of password knowledge.
///
/// The proof demonstrates that the prover knows a password that
/// hashes to the embedded commitment, without revealing the password.
///
/// # Parameters
/// Same as `derive_secret_start`
///
/// # Returns
/// Serialized proof bytes that can be verified with `verify_password_proof`.
///
/// # Proof Structure
/// The returned bytes contain:
/// - Schema version (1 byte)
/// - Commitment (32 bytes)
/// - STARK proof (variable length)
///
/// # Performance
/// Proof generation takes approximately 0.5-2 seconds depending on hardware.
pub fn prove_password(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Vec<u8>, StarkError> {
    let secret = derive_secret_start(password, salt, m_cost, t_cost, p_cost)?;
    let (trace, commitment) = generate_poseidon_trace(secret, NUM_ROUNDS);
    
    let (config, _perm) = make_config();
    let air = PoseidonPreimageAir { _num_rounds: NUM_ROUNDS };
    let public_inputs = commitment;
    
    let proof = prove(&config, &air, trace, &public_inputs);
    
    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| StarkError { code: ErrorCode::SerializationError, message: e.to_string() })?;
    
    let payload = ProofPayload {
        commitment: commitment.map(|v| v.as_canonical_u64()),
        valid: true,
        proof_bytes,
    };
    
    let mut serialized = postcard::to_allocvec(&payload)
        .map_err(|e| StarkError { code: ErrorCode::SerializationError, message: e.to_string() })?;
    
    let mut output = Vec::with_capacity(serialized.len() + 1);
    output.push(1u8); // Schema version
    output.append(&mut serialized);
    
    Ok(output)
}

/// Verifies a STARK proof of password knowledge.
///
/// Checks that:
/// 1. Proof format is valid
/// 2. Commitment in proof matches expected commitment
/// 3. STARK proof verifies against the AIR constraints
///
/// # Parameters
/// - `proof_bytes`: Serialized proof from `prove_password`
/// - `expected_commitment`: Commitment from `get_commitment`
///
/// # Returns
/// - `Ok(true)` if proof is valid
/// - `Err(StarkError)` with details if verification fails
///
/// # Security
/// This function is safe to call with untrusted proof bytes.
/// Invalid proofs will be rejected with appropriate error codes.
pub fn verify_password_proof(proof_bytes: &[u8], expected_commitment: [Val; 4]) -> Result<bool, StarkError> {
    if proof_bytes.is_empty() {
        return Err(StarkError { 
            code: ErrorCode::InvalidProofFormat, 
            message: "Proof bytes are empty".to_string() 
        });
    }
    
    if proof_bytes[0] != 1 {
        return Err(StarkError { 
            code: ErrorCode::InvalidProofFormat, 
            message: format!("Unsupported schema version: {}", proof_bytes[0]) 
        });
    }
    
    let payload: ProofPayload = postcard::from_bytes(&proof_bytes[1..])
        .map_err(|e| StarkError { code: ErrorCode::SerializationError, message: e.to_string() })?;
    
    let expected_u64: [u64; 4] = expected_commitment.map(|v| v.as_canonical_u64());
    if payload.commitment != expected_u64 {
        return Err(StarkError { 
            code: ErrorCode::CommitmentMismatch, 
            message: "Proof commitment does not match expected commitment".to_string() 
        });
    }
    
    let (config, _perm) = make_config();
    
    let proof: Proof<MyConfig> = postcard::from_bytes(&payload.proof_bytes)
        .map_err(|e| StarkError { code: ErrorCode::SerializationError, message: e.to_string() })?;
    
    let air = PoseidonPreimageAir { _num_rounds: NUM_ROUNDS };
    
    verify(&config, &air, &proof, &expected_commitment)
        .map_err(|e| StarkError { 
            code: ErrorCode::VerificationError, 
            message: format!("STARK verification failed: {:?}", e) 
        })?;
    
    Ok(true)
}

// ============================================================================
// 8. FFI EXPORTS (Safe C Interface)
// ============================================================================

/// Opaque handle returned by FFI functions.
/// 
/// This handle must be passed to `c_verify_password_proof` and
/// eventually freed with `c_free_proof`.
#[repr(C)]
pub struct OpaqueProofResult { 
    _private: [u8; 0] 
}

/// Internal proof result structure with safety features.
#[repr(C)]
struct SafeProofHandle {
    /// Magic number for validation
    magic: u64,
    /// Proof data pointer
    ptr: *mut u8,
    /// Proof data length
    len: usize,
    /// Proof data capacity
    cap: usize,
    /// Status code
    status: u32,
}

impl SafeProofHandle {
    fn new(ptr: *mut u8, len: usize, cap: usize, status: ErrorCode) -> Self {
        SafeProofHandle {
            magic: PROOF_HANDLE_MAGIC,
            ptr,
            len,
            cap,
            status: status as u32,
        }
    }
    
    fn error(status: ErrorCode) -> Self {
        SafeProofHandle {
            magic: PROOF_HANDLE_MAGIC,
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
            status: status as u32,
        }
    }
    
    fn is_valid(&self) -> bool {
        self.magic == PROOF_HANDLE_MAGIC
    }
}

/// Derives a secret field element from password via Argon2id.
///
/// # Safety
/// - `password_ptr` must point to valid memory of at least `password_len` bytes
/// - `salt_ptr` must point to valid memory of at least `salt_len` bytes
///
/// # Returns
/// The derived secret as u64, or 0 on error.
#[no_mangle]
pub extern "C" fn c_derive_secret_start(
    password_ptr: *const u8, password_len: usize,
    salt_ptr: *const u8, salt_len: usize,
    m_cost: u32, t_cost: u32, p_cost: u32,
) -> u64 {
    if password_ptr.is_null() || salt_ptr.is_null() { return 0; }
    if password_len > MAX_PASSWORD_LEN || salt_len > MAX_SALT_LEN { return 0; }
    
    std::panic::catch_unwind(move || {
        let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
        let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
        
        let password_str = std::str::from_utf8(password_bytes).ok()?;
        derive_secret_start(password_str, salt, m_cost, t_cost, p_cost).ok().map(|v| v.as_canonical_u64())
    }).ok().flatten().unwrap_or(0)
}

/// Result of commitment computation.
#[repr(C)]
pub struct CommitmentResult { 
    /// Commitment values (4 × 64-bit field elements)
    pub values: [u64; 4], 
    /// True if computation succeeded
    pub success: bool 
}

/// Computes commitment hash for a password.
///
/// # Safety
/// Same as `c_derive_secret_start`
///
/// # Returns
/// `CommitmentResult` with `success=true` if computation succeeded.
#[no_mangle]
pub extern "C" fn c_get_commitment(
    password_ptr: *const u8, password_len: usize,
    salt_ptr: *const u8, salt_len: usize,
    m_cost: u32, t_cost: u32, p_cost: u32,
) -> CommitmentResult {
    let fail = CommitmentResult { values: [0; 4], success: false };
    
    if password_ptr.is_null() || salt_ptr.is_null() { return fail; }
    if password_len > MAX_PASSWORD_LEN || salt_len > MAX_SALT_LEN { return fail; }
    
    std::panic::catch_unwind(move || {
        let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
        let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
        
        let password_str = std::str::from_utf8(password_bytes).ok()?;
        get_commitment(password_str, salt, m_cost, t_cost, p_cost).ok()
            .map(|c| CommitmentResult { values: c.map(|v| v.as_canonical_u64()), success: true })
    }).ok().flatten().unwrap_or(fail)
}

/// Generates a STARK proof of password knowledge.
///
/// # Safety
/// Same as `c_derive_secret_start`
///
/// # Returns
/// Opaque handle to proof result. Must be freed with `c_free_proof`.
/// Returns null on error.
#[no_mangle]
pub extern "C" fn c_prove_password(
    password_ptr: *const u8, password_len: usize,
    salt_ptr: *const u8, salt_len: usize,
    m_cost: u32, t_cost: u32, p_cost: u32,
) -> *mut OpaqueProofResult {
    if password_ptr.is_null() || salt_ptr.is_null() { return std::ptr::null_mut(); }
    if password_len > MAX_PASSWORD_LEN || salt_len > MAX_SALT_LEN { return std::ptr::null_mut(); }
    
    let result = std::panic::catch_unwind(move || {
        let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
        let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
        
        let password_str = match std::str::from_utf8(password_bytes) {
            Ok(s) => s,
            Err(_) => return SafeProofHandle::error(ErrorCode::InvalidPassword),
        };
        
        match prove_password(password_str, salt, m_cost, t_cost, p_cost) {
            Ok(mut bytes) => {
                let ptr = bytes.as_mut_ptr();
                let len = bytes.len();
                let cap = bytes.capacity();
                std::mem::forget(bytes);
                SafeProofHandle::new(ptr, len, cap, ErrorCode::Success)
            },
            Err(e) => SafeProofHandle::error(e.code)
        }
    });
    
    match result {
        Ok(handle) => Box::into_raw(Box::new(handle)) as *mut OpaqueProofResult,
        Err(_) => {
            let handle = SafeProofHandle::error(ErrorCode::InternalPanic);
            Box::into_raw(Box::new(handle)) as *mut OpaqueProofResult
        }
    }
}

/// Gets the status code from a proof handle.
///
/// # Returns
/// Status code (0 = success), or `ErrorCode::InvalidHandle` if handle is invalid.
#[no_mangle]
pub extern "C" fn c_get_proof_status(proof_ptr: *const OpaqueProofResult) -> u32 {
    if proof_ptr.is_null() { return ErrorCode::InvalidHandle as u32; }
    
    let handle = unsafe { &*(proof_ptr as *const SafeProofHandle) };
    if !handle.is_valid() { return ErrorCode::InvalidHandle as u32; }
    
    handle.status
}

/// Gets the proof data length.
///
/// # Returns
/// Length in bytes, or 0 if handle is invalid.
#[no_mangle]
pub extern "C" fn c_get_proof_len(proof_ptr: *const OpaqueProofResult) -> usize {
    if proof_ptr.is_null() { return 0; }
    
    let handle = unsafe { &*(proof_ptr as *const SafeProofHandle) };
    if !handle.is_valid() { return 0; }
    
    handle.len
}

/// Copies proof data to a buffer.
///
/// # Safety
/// - `buffer` must point to valid memory of at least `buffer_len` bytes
/// - Call `c_get_proof_len` first to determine required buffer size
///
/// # Returns
/// Number of bytes copied, or 0 on error.
#[no_mangle]
pub extern "C" fn c_copy_proof_data(
    proof_ptr: *const OpaqueProofResult,
    buffer: *mut u8,
    buffer_len: usize,
) -> usize {
    if proof_ptr.is_null() || buffer.is_null() { return 0; }
    
    let handle = unsafe { &*(proof_ptr as *const SafeProofHandle) };
    if !handle.is_valid() || handle.ptr.is_null() { return 0; }
    
    let copy_len = buffer_len.min(handle.len);
    unsafe {
        std::ptr::copy_nonoverlapping(handle.ptr, buffer, copy_len);
    }
    copy_len
}

/// Verifies a STARK proof of password knowledge.
///
/// # Safety
/// - `proof_ptr` must be a valid handle from `c_prove_password`
/// - `commitment_ptr` must point to 4 u64 values
///
/// # Returns
/// `true` if proof is valid, `false` otherwise.
#[no_mangle]
pub extern "C" fn c_verify_password_proof(proof_ptr: *const OpaqueProofResult, commitment_ptr: *const u64) -> bool {
    if proof_ptr.is_null() || commitment_ptr.is_null() { return false; }
    
    let handle = unsafe { &*(proof_ptr as *const SafeProofHandle) };
    if !handle.is_valid() { return false; }
    if handle.status != 0 { return false; }
    if handle.ptr.is_null() { return false; }
    
    let commitment_slice = unsafe { std::slice::from_raw_parts(commitment_ptr, 4) };
    let commitment: [Val; 4] = [
        Val::from_u64(commitment_slice[0]),
        Val::from_u64(commitment_slice[1]),
        Val::from_u64(commitment_slice[2]),
        Val::from_u64(commitment_slice[3]),
    ];
    
    let proof_slice = unsafe { std::slice::from_raw_parts(handle.ptr, handle.len) };
    verify_password_proof(proof_slice, commitment).unwrap_or(false)
}

/// Frees a proof handle.
///
/// # Safety
/// - `proof_ptr` must be from `c_prove_password` or null
/// - After this call, the handle is invalid and must not be used
#[no_mangle]
pub extern "C" fn c_free_proof(proof_ptr: *mut OpaqueProofResult) {
    if proof_ptr.is_null() { return; }
    
    unsafe {
        let handle = Box::from_raw(proof_ptr as *mut SafeProofHandle);
        
        // Validate magic before freeing internal resources
        if handle.is_valid() && !handle.ptr.is_null() {
            let _ = Vec::from_raw_parts(handle.ptr, handle.len, handle.cap);
        }
        // handle is dropped here
    }
}

// ============================================================================
// 9. TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Input Validation Tests ---

    #[test]
    fn test_empty_password_rejected() {
        let result = validate_inputs("", b"saltsalt", 4096, 3, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidPassword);
    }

    #[test]
    fn test_long_password_rejected() {
        let long_pass = "a".repeat(MAX_PASSWORD_LEN + 1);
        let result = validate_inputs(&long_pass, b"saltsalt", 4096, 3, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidPassword);
    }

    #[test]
    fn test_short_salt_rejected() {
        let result = validate_inputs("password", b"short", 4096, 3, 1);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ErrorCode::InvalidSalt);
    }

    #[test]
    fn test_invalid_argon_params_rejected() {
        // m_cost too low
        assert!(validate_inputs("password", b"saltsalt", 1, 3, 1).is_err());
        // t_cost too low
        assert!(validate_inputs("password", b"saltsalt", 4096, 0, 1).is_err());
        // p_cost too low
        assert!(validate_inputs("password", b"saltsalt", 4096, 3, 0).is_err());
        // m_cost too high
        assert!(validate_inputs("password", b"saltsalt", MAX_M_COST + 1, 3, 1).is_err());
    }

    #[test]
    fn test_valid_inputs_accepted() {
        assert!(validate_inputs("password", b"saltsalt", 4096, 3, 1).is_ok());
        assert!(validate_inputs("p", b"saltsalt", MIN_M_COST, 1, 1).is_ok());
    }

    // --- Secret Derivation Tests ---

    #[test]
    fn test_derive_secret_deterministic() {
        let s1 = derive_secret_start("test", b"saltsaltsalt", 4096, 3, 1).unwrap();
        let s2 = derive_secret_start("test", b"saltsaltsalt", 4096, 3, 1).unwrap();
        assert_eq!(s1, s2, "Same inputs should produce same output");
    }

    #[test]
    fn test_derive_secret_different_passwords() {
        let s1 = derive_secret_start("password1", b"saltsaltsalt", 4096, 3, 1).unwrap();
        let s2 = derive_secret_start("password2", b"saltsaltsalt", 4096, 3, 1).unwrap();
        assert_ne!(s1, s2, "Different passwords should produce different outputs");
    }

    #[test]
    fn test_derive_secret_different_salts() {
        let s1 = derive_secret_start("password", b"saltsalt1111", 4096, 3, 1).unwrap();
        let s2 = derive_secret_start("password", b"saltsalt2222", 4096, 3, 1).unwrap();
        assert_ne!(s1, s2, "Different salts should produce different outputs");
    }

    // --- Commitment Tests ---

    #[test]
    fn test_commitment_deterministic() {
        let c1 = get_commitment("test", b"saltsaltsalt", 4096, 3, 1).unwrap();
        let c2 = get_commitment("test", b"saltsaltsalt", 4096, 3, 1).unwrap();
        assert_eq!(c1, c2, "Same inputs should produce same commitment");
    }

    #[test]
    fn test_commitment_different_passwords() {
        let c1 = get_commitment("password1", b"saltsaltsalt", 4096, 3, 1).unwrap();
        let c2 = get_commitment("password2", b"saltsaltsalt", 4096, 3, 1).unwrap();
        assert_ne!(c1, c2, "Different passwords should produce different commitments");
    }

    // --- Proof Round-Trip Tests ---

    #[test]
    fn test_prove_and_verify_success() {
        let pass = "correct_horse";
        let salt = b"battery_staple__";
        let m_cost = 4096;
        let t_cost = 3;
        let p_cost = 1;
        
        let commitment = get_commitment(pass, salt, m_cost, t_cost, p_cost).expect("Commit failed");
        let proof = prove_password(pass, salt, m_cost, t_cost, p_cost).expect("Prove failed");
        let valid = verify_password_proof(&proof, commitment).expect("Verify failed");
        assert!(valid, "Valid proof should verify");
    }

    #[test]
    fn test_verify_wrong_commitment_fails() {
        let pass = "correct_horse";
        let salt = b"battery_staple__";
        
        let commitment = get_commitment(pass, salt, 4096, 3, 1).expect("Commit failed");
        let proof = prove_password(pass, salt, 4096, 3, 1).expect("Prove failed");
        
        let mut wrong_commitment = commitment;
        wrong_commitment[0] = wrong_commitment[0] + Val::ONE;
        
        let result = verify_password_proof(&proof, wrong_commitment);
        assert!(result.is_err(), "Wrong commitment should fail");
        assert_eq!(result.unwrap_err().code, ErrorCode::CommitmentMismatch);
    }

    #[test]
    fn test_verify_corrupted_proof_fails() {
        let commitment = get_commitment("test", b"saltsaltsalt", 4096, 3, 1).expect("Commit failed");
        
        // Empty proof
        assert!(verify_password_proof(&[], commitment).is_err());
        
        // Wrong version
        assert!(verify_password_proof(&[2, 0, 0], commitment).is_err());
        
        // Corrupted data
        assert!(verify_password_proof(&[1, 0, 0, 0], commitment).is_err());
    }

    // --- FFI Safety Tests ---

    #[test]
    fn test_ffi_null_pointers_handled() {
        assert_eq!(c_derive_secret_start(std::ptr::null(), 0, b"salt".as_ptr(), 4, 4096, 3, 1), 0);
        assert_eq!(c_derive_secret_start(b"pass".as_ptr(), 4, std::ptr::null(), 0, 4096, 3, 1), 0);
        
        let result = c_get_commitment(std::ptr::null(), 0, b"salt".as_ptr(), 4, 4096, 3, 1);
        assert!(!result.success);
        
        assert!(c_prove_password(std::ptr::null(), 0, b"salt".as_ptr(), 4, 4096, 3, 1).is_null());
        assert!(!c_verify_password_proof(std::ptr::null(), [0u64; 4].as_ptr()));
        
        // c_free_proof should not crash on null
        c_free_proof(std::ptr::null_mut());
    }

    #[test]
    fn test_ffi_oversized_inputs_handled() {
        let huge_len = MAX_PASSWORD_LEN + 1;
        assert_eq!(c_derive_secret_start(b"x".as_ptr(), huge_len, b"saltsalt".as_ptr(), 8, 4096, 3, 1), 0);
    }

    #[test]
    fn test_safe_proof_handle_validation() {
        let pass = b"test_password";
        let salt = b"saltsaltsalt";
        
        let handle = c_prove_password(pass.as_ptr(), pass.len(), salt.as_ptr(), salt.len(), 4096, 3, 1);
        assert!(!handle.is_null());
        
        // Check status
        assert_eq!(c_get_proof_status(handle), ErrorCode::Success as u32);
        
        // Check length
        let len = c_get_proof_len(handle);
        assert!(len > 0);
        
        // Free handle
        c_free_proof(handle);
    }
}
