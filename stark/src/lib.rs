extern crate alloc;
use alloc::vec::Vec;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use p3_field::{AbstractField, PrimeField64, Field};
use p3_goldilocks::{Goldilocks, DiffusionMatrixGoldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS, HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_uni_stark::{prove, verify, StarkConfig};
use p3_challenger::{DuplexChallenger, CanObserve};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixHL};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};

// ----------------------------------------------------------------------------
// 1. CONFIGURATION & TYPES
// ----------------------------------------------------------------------------

type Val = Goldilocks;

const WIDTH: usize = 8;
const ALPHA: u64 = 7;

// Helper to convert constants
fn to_goldilocks_array<const N: usize>(input: [u64; N]) -> [Goldilocks; N] {
    let mut output = [Goldilocks::from_canonical_u64(0); N];
    for i in 0..N {
        output[i] = Goldilocks::from_canonical_u64(input[i]);
    }
    output
}

// ----------------------------------------------------------------------------
// 2. THE AIR
// ----------------------------------------------------------------------------
#[derive(Clone)]
struct RepeatedSquaringAir {
    final_val: Val,
}

impl BaseAir<Val> for RepeatedSquaringAir {
    fn width(&self) -> usize { 1 }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for RepeatedSquaringAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        let five = AB::Expr::from_canonical_u64(5);
        let squared = local[0] * local[0];
        
        // Only enforce transition on non-terminal rows
        builder.when_transition().assert_eq(next[0], squared + five);
        
        builder.when_last_row().assert_eq(local[0], AB::Expr::from(self.final_val));
    }
}

// ----------------------------------------------------------------------------
// 3. TRACE & HELPERS
// ----------------------------------------------------------------------------
fn generate_trace(start_val: Val, num_steps: usize) -> (RowMajorMatrix<Val>, Val) {
    let mut values = Vec::with_capacity(num_steps);
    let mut current = start_val;
    values.push(current);
    for _ in 0..num_steps - 1 {
        current = current * current + Val::from_canonical_u64(5);
        values.push(current);
    }
    (RowMajorMatrix::new(values, 1), current)
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

fn derive_secret_start(password_str: &str, salt_input: u64) -> Val {
    let argon2 = Argon2::default();
    let salt_bytes = salt_input.to_le_bytes();
    let salt_string = SaltString::encode_b64(&salt_bytes).expect("Encoding failed");
    let password_hash = argon2.hash_password(password_str.as_bytes(), &salt_string).expect("Argon2 failed");
    let output = password_hash.hash.expect("No hash");
    let bytes = output.as_bytes();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    Val::from_canonical_u64(u64::from_le_bytes(buf))
}

// Must be power of 2 for FRI
const PROOF_STEPS: usize = 64; 

#[wasm_bindgen]
pub fn get_commitment(password_str: &str, salt: u64) -> u64 {
    let start_val = derive_secret_start(password_str, salt);
    let mut current = start_val;
    for _ in 0..PROOF_STEPS - 1 {
        current = current * current + Val::from_canonical_u64(5);
    }
    current.as_canonical_u64()
}

// ----------------------------------------------------------------------------
// 4. REAL PROOF GENERATION
// ----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ProofPayload {
    commitment: u64,
    valid: bool,
    proof_bytes: Vec<u8>,
}

#[wasm_bindgen]
pub fn prove_password(password_str: &str, salt: u64, nonce: u64) -> Vec<u8> {
    let start_val = derive_secret_start(password_str, salt);
    let (trace, final_val) = generate_trace(start_val, PROOF_STEPS);
    
    // 1. Manual Safety Check (Fast Fail)
    for i in 0..PROOF_STEPS - 1 {
        let local = trace.values[i];
        let next = trace.values[i+1];
        if next != local * local + Val::from_canonical_u64(5) {
             panic!("Invalid Trace");
        }
    }
    if trace.values.last().unwrap() != &final_val {
        panic!("Invalid Boundary");
    }

    // 2. Setup Config
    // Poseidon2 w/ Goldilocks Constants
    let perm = Poseidon2::<Val, Poseidon2ExternalMatrixHL, DiffusionMatrixGoldilocks, WIDTH, ALPHA>::new(
        8, // Rounds F
        HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS.map(to_goldilocks_array).to_vec(),
        Poseidon2ExternalMatrixHL,
        22, // Rounds P
        to_goldilocks_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
        DiffusionMatrixGoldilocks,
    );
    
    // Components
    // Hash: Width 8, Rate 4, Output 4.
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    
    // Compress: Arity 2. Chunk 4. Width 8.
    // 4 * 2 <= 8. Correct.
    let compress = TruncatedPermutation::<_, 2, 4, 8>::new(perm.clone()); 
    
    // ValMmcs: Merkle Tree over Val. Digest size inferred as 4 from compress.
    // Explicitly specify P=Val, PW=Val::Packing.
    let val_mmcs = FieldMerkleTreeMmcs::<Val, <Val as Field>::Packing, _, _, 4>::new(hash.clone(), compress.clone());

    // ChallengeMmcs: Same (simplification)
    let _chall_mmcs = val_mmcs.clone();
    
    // DFT
    let dft = Radix2DitParallel;
    
    // Challenger
    // DuplexChallenger<F, P, WIDTH, RATE>
    let mut challenger = DuplexChallenger::<_, _, 8, 4>::new(perm.clone());
    challenger.observe(Val::from_canonical_u64(nonce));
    
    // FRI
    let fri_config = FriConfig {
        log_blowup: 1, 
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: val_mmcs.clone(),
    };
    // Log degree bound. PROOF_STEPS = 64 = 2^6.
    let log_n = 6;
    let pcs = TwoAdicFriPcs::new(
        log_n,
        dft,
        val_mmcs,
        fri_config,
    );
    
    let config: StarkConfig<_, Val, _> = StarkConfig::new(pcs);
    
    // 3. Prove
    let air = RepeatedSquaringAir { final_val };
    let proof = prove(&config, &air, &mut challenger.clone(), trace, &vec![]);
    
    let proof_bytes = postcard::to_allocvec(&proof).unwrap_or(vec![0xDE, 0xAD]);

    let payload = ProofPayload {
        commitment: final_val.as_canonical_u64(),
        valid: true,
        proof_bytes: proof_bytes,
    };
    
    postcard::to_allocvec(&payload).unwrap_or_default()
}

#[wasm_bindgen]
pub fn verify_password_proof(proof_bytes: &[u8], expected_commitment: u64, nonce: u64) -> bool {
    let payload: ProofPayload = match postcard::from_bytes(proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    if payload.commitment != expected_commitment {
        return false;
    }
    
    let perm = Poseidon2::<Val, Poseidon2ExternalMatrixHL, DiffusionMatrixGoldilocks, WIDTH, ALPHA>::new(
        8,
        HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS.map(to_goldilocks_array).to_vec(),
        Poseidon2ExternalMatrixHL,
        22,
        to_goldilocks_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
        DiffusionMatrixGoldilocks,
    );
    
    // Reconstruct types for Deserialization
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let compress = TruncatedPermutation::<_, 2, 4, 8>::new(perm.clone()); 
    let val_mmcs = FieldMerkleTreeMmcs::<Val, <Val as Field>::Packing, _, _, 4>::new(hash.clone(), compress.clone());
    let dft = Radix2DitParallel;
    let mut challenger = DuplexChallenger::<_, _, 8, 4>::new(perm.clone());
    challenger.observe(Val::from_canonical_u64(nonce));
    
    let fri_config = FriConfig {
        log_blowup: 1, 
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: val_mmcs.clone(),
    };
    let log_n = 6;
    let pcs = TwoAdicFriPcs::new(log_n, dft, val_mmcs, fri_config);
    let config: StarkConfig<_, Val, _> = StarkConfig::new(pcs);
    
    // Type Aliases for Postcard
    type MyPerm = Poseidon2<Val, Poseidon2ExternalMatrixHL, DiffusionMatrixGoldilocks, 8, 7>;
    type MyHash = PaddingFreeSponge<MyPerm, 8, 4, 4>;
    type MyCompress = TruncatedPermutation<MyPerm, 2, 4, 8>;
    type MyMmcs = FieldMerkleTreeMmcs<Val, <Val as Field>::Packing, MyHash, MyCompress, 4>;
    type MyPcs = TwoAdicFriPcs<Val, Radix2DitParallel, MyMmcs, MyMmcs>;
    type MyConfig = StarkConfig<MyPcs, Val, DuplexChallenger<Val, MyPerm, 8, 4>>;
    
    let proof: p3_uni_stark::Proof<MyConfig> = match postcard::from_bytes(&payload.proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let air = RepeatedSquaringAir { final_val: Val::from_canonical_u64(expected_commitment) };
    
    verify(&config, &air, &mut challenger, &proof, &vec![]).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_flow() {
        let password = "correct_horse_battery_staple";
        let salt = 123456789;
        let nonce = 0;

        // 1. Get expected commitment
        println!("Deriving commitment...");
        let commitment = get_commitment(password, salt);
        println!("Commitment: {}", commitment);
        
        // 2. Generate Proof
        println!("Generating proof...");
        let proof_bytes = prove_password(password, salt, nonce);
        println!("Proof size: {} bytes", proof_bytes.len());
        assert!(!proof_bytes.is_empty());

        // 3. Verify Proof
        println!("Verifying proof...");
        let valid = verify_password_proof(&proof_bytes, commitment, nonce);
        assert!(valid, "Proof should verify successfully");
        
        // 4. Verify with wrong commitment
        println!("Verifying with wrong commitment...");
        let invalid = verify_password_proof(&proof_bytes, commitment + 1, nonce);
        assert!(!invalid, "Proof should fail with wrong commitment");

        // 5. Verify with wrong nonce
        println!("Verifying with wrong nonce...");
        let invalid_nonce = verify_password_proof(&proof_bytes, commitment, nonce + 1);
        assert!(!invalid_nonce, "Proof should fail with wrong nonce");
    }

    #[test]
    fn test_trace_logic() {
        let start = Val::from_canonical_u64(10);
        let (trace, end) = generate_trace(start, 4);
        assert_eq!(trace.height(), 4);
        assert_eq!(trace.width(), 1);
        println!("End val: {:?}", end);
    }
}