extern crate alloc;
use alloc::vec::Vec;
use argon2::{Argon2, PasswordHasher, Algorithm, Version, Params};
use argon2::password_hash::SaltString;
use p3_field::{AbstractField, PrimeField64, Field, AbstractExtensionField};
use p3_field::extension::BinomialExtensionField;
use p3_goldilocks::{Goldilocks, DiffusionMatrixGoldilocks, HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS, HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_uni_stark::{prove, verify, StarkConfig, Proof};
use p3_challenger::{DuplexChallenger, CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_dft::Radix2DitParallel;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixHL};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation, CryptographicHasher, Hash, PseudoCompressionFunction};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use rand::{Rng, thread_rng};

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;


// ----------------------------------------------------------------------------
// 1. CONFIGURATION & TYPES
// ----------------------------------------------------------------------------

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;

const WIDTH: usize = 8;
const ALPHA: u64 = 7;

fn to_goldilocks_array<const N: usize>(input: [u64; N]) -> [Goldilocks; N] {
    let mut output = [Goldilocks::from_canonical_u64(0); N];
    for i in 0..N {
        output[i] = Goldilocks::from_canonical_u64(input[i]);
    }
    output
}

#[derive(Clone)]
struct ExtensionHasher<ValHasher>(ValHasher);

impl<ValHasher> CryptographicHasher<Challenge, [Challenge; 2]> for ExtensionHasher<ValHasher> 
where 
    ValHasher: CryptographicHasher<Val, [Val; 4]>,
{
    fn hash_iter<I>(&self, input: I) -> [Challenge; 2]
    where
        I: IntoIterator<Item = Challenge>,
    {
        let flat_input: Vec<Val> = input.into_iter()
            .flat_map(|x| x.as_base_slice().to_vec())
            .collect();
        let res_val = self.0.hash_iter(flat_input); 
        
        // Reconstruct extension elements
        let c1 = Challenge::from_base_slice(&res_val[0..2]);
        let c2 = Challenge::from_base_slice(&res_val[2..4]);
        [c1, c2]
    }
}

#[derive(Clone)]
struct ExtensionCompressor<C>(C);

impl<C> PseudoCompressionFunction<[Challenge; 2], 2> for ExtensionCompressor<C>
where C: PseudoCompressionFunction<[Val; 4], 2> 
{
    fn compress(&self, input: [[Challenge; 2]; 2]) -> [Challenge; 2] {
        let mut row0 = [Val::zero(); 4];
        let mut row1 = [Val::zero(); 4];
        
        let s00 = input[0][0].as_base_slice(); 
        let s01 = input[0][1].as_base_slice();
        row0[0] = s00[0]; row0[1] = s00[1];
        row0[2] = s01[0]; row0[3] = s01[1];

        let s10 = input[1][0].as_base_slice(); 
        let s11 = input[1][1].as_base_slice();
        row1[0] = s10[0]; row1[1] = s10[1];
        row1[2] = s11[0]; row1[3] = s11[1];
        
        let res_val = self.0.compress([row0, row1]); 
        
        let c1 = Challenge::from_base_slice(&res_val[0..2]);
        let c2 = Challenge::from_base_slice(&res_val[2..4]);
        [c1, c2]
    }
}

// Wrapper for Challenger
#[derive(Clone)]
struct ExtensionChallenger<C>(C);

// CanSampleBits
impl<C: CanSampleBits<usize>> CanSampleBits<usize> for ExtensionChallenger<C> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.0.sample_bits(bits)
    }
}

// Observe Val
impl<C: CanObserve<Val>> CanObserve<Val> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Val) {
        self.0.observe(value);
    }
}
impl<C: CanSample<Val>> CanSample<Val> for ExtensionChallenger<C> {
    fn sample(&mut self) -> Val {
        self.0.sample()
    }
}

// Observe Arrays
impl<C: CanObserve<[Val; N]>, const N: usize> CanObserve<[Val; N]> for ExtensionChallenger<C> {
    fn observe(&mut self, value: [Val; N]) {
        self.0.observe(value);
    }
}
// Observe Hash<Val>
// Replaced transmute with generic decomposition if possible, or assume Hash is iterable/convertible
impl<C: CanObserve<[Val; N]>, M, const N: usize> CanObserve<Hash<Val, M, N>> for ExtensionChallenger<C> 
where Hash<Val, M, N>: Into<[Val; N]> 
{
    fn observe(&mut self, value: Hash<Val, M, N>) {
        let arr: [Val; N] = value.into();
        self.0.observe(arr);
    }
}
// Observe Vec<Val>
impl<C: CanObserve<Vec<Val>>> CanObserve<Vec<Val>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Vec<Val>) {
        self.0.observe(value);
    }
}

// Extension Support
impl<C: CanObserve<Val>> CanObserve<Challenge> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Challenge) {
        for &v in value.as_base_slice() {
            self.0.observe(v);
        }
    }
}
impl<C: CanSample<Val>> CanSample<Challenge> for ExtensionChallenger<C> {
    fn sample(&mut self) -> Challenge {
        let a = self.0.sample();
        let b = self.0.sample();
        Challenge::from_base_slice(&[a, b])
    }
}
// Observe [Challenge; N]
impl<C: CanObserve<Val>, const N: usize> CanObserve<[Challenge; N]> for ExtensionChallenger<C> {
    fn observe(&mut self, values: [Challenge; N]) {
        for v in values {
            self.observe(v);
        }
    }
}
// Observe Hash<Challenge> (Flattening)
impl<C: CanObserve<Val>, M, const N: usize> CanObserve<Hash<Challenge, M, N>> for ExtensionChallenger<C> 
where Hash<Challenge, M, N>: Into<[Challenge; N]>
{
    fn observe(&mut self, value: Hash<Challenge, M, N>) {
        let arr: [Challenge; N] = value.into();
        for x in arr {
             self.observe(x); 
        }
    }
}

// FieldChallenger Implementations
impl<C> FieldChallenger<Val> for ExtensionChallenger<C> 
where C: FieldChallenger<Val> + Clone + Sync + CanSampleBits<usize>
{}

impl<C> FieldChallenger<Challenge> for ExtensionChallenger<C> 
where C: CanObserve<Val> + CanSample<Val> + Clone + Sync + CanSampleBits<usize> + CanObserve<[Val; 4]>
{}

// GrindingChallenger
impl<C> GrindingChallenger for ExtensionChallenger<C> 
where C: GrindingChallenger<Witness = Val> + CanSampleBits<usize>
{
    type Witness = Val;
    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.0.grind(bits)
    }
}

// ----------------------------------------------------------------------------
// 2. THE AIR
// ----------------------------------------------------------------------------
#[derive(Clone)]
struct RepeatedSquaringAir {
    final_val: Val,
}

impl BaseAir<Val> for RepeatedSquaringAir {
    fn width(&self) -> usize { 2 }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for RepeatedSquaringAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let next = main.row_slice(1);
        
        let val_local = local[0];
        let sel_local = local[1];
        
        let val_next = next[0];
        let sel_next = next[1];

        let five = AB::Expr::from_canonical_u64(5);
        let squared = val_local * val_local;
        
        builder.when_transition()
            .when(sel_local)
            .assert_eq(val_next, squared + five);

        builder.assert_eq(sel_local * (sel_local - AB::Expr::one()), AB::Expr::zero());
        
        builder.when_transition()
            .when(sel_next)
            .assert_eq(sel_local, AB::Expr::one());

        let transition_end = sel_local - sel_next;
        builder.when_transition()
            .when(transition_end)
            .assert_eq(val_next, AB::Expr::from(self.final_val));
    }
}

// ----------------------------------------------------------------------------
// 3. TRACE & HELPERS
// ----------------------------------------------------------------------------

const PROOF_STEPS: usize = 16384; 

fn generate_trace(start_val: Val, num_steps: usize) -> (RowMajorMatrix<Val>, Val) {
    let padding_margin = 128; // Increased from 64 for stronger ZK per user request
    let min_height = num_steps + 1 + padding_margin; 
    let height = min_height.next_power_of_two();
    
    let mut values = Vec::with_capacity(height * 2);
    let mut rng = thread_rng();

    let mut current = start_val;
    
    for _ in 0..num_steps {
        values.push(current);       
        values.push(Val::one());    
        current = current * current + Val::from_canonical_u64(5);
    }
    
    let final_val = current;
    values.push(final_val);
    values.push(Val::zero()); 

    for _ in (num_steps + 1)..height {
        values.push(Val::from_canonical_u64(rng.gen()));
        values.push(Val::zero());
    }

    (RowMajorMatrix::new(values, 2), final_val)
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

fn derive_secret_start(password_str: &str, salt: &[u8]) -> Val {
    // Production parameters for Argon2
    // m=15360 (15 MiB), t=3, p=1
    let params = Params::new(15360, 3, 1, Some(32)).unwrap();
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    
    let salt_string = SaltString::encode_b64(salt).expect("Salt encoding failed");
    let password_hash = argon2.hash_password(password_str.as_bytes(), &salt_string).expect("Argon2 failed");
    let output = password_hash.hash.expect("No hash");
    let bytes = output.as_bytes();
    
    // Use first 8 bytes for Val (field element)
    let mut buf = [0u8; 8];
    if bytes.len() >= 8 {
        buf.copy_from_slice(&bytes[0..8]);
    }
    Val::from_canonical_u64(u64::from_le_bytes(buf))
}

#[wasm_bindgen]
pub fn get_commitment(password_str: &str, salt: &[u8]) -> u64 {
    let start_val = derive_secret_start(password_str, salt);
    let mut current = start_val;
    for _ in 0..PROOF_STEPS {
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
pub fn prove_password(password_str: &str, salt: &[u8], nonce: u64) -> Result<Vec<u8>, JsValue> {
    if salt.len() < 16 {
         return Err(JsValue::from_str("Salt must be at least 16 bytes"));
    }

    let start_val = derive_secret_start(password_str, salt);
    let (trace, final_val) = generate_trace(start_val, PROOF_STEPS);
    
    let perm = Poseidon2::<Val, Poseidon2ExternalMatrixHL, DiffusionMatrixGoldilocks, WIDTH, ALPHA>::new(
        8, 
        HL_GOLDILOCKS_8_EXTERNAL_ROUND_CONSTANTS.map(to_goldilocks_array).to_vec(),
        Poseidon2ExternalMatrixHL,
        22, 
        to_goldilocks_array(HL_GOLDILOCKS_8_INTERNAL_ROUND_CONSTANTS).to_vec(),
        DiffusionMatrixGoldilocks,
    );
    
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let compress = TruncatedPermutation::<_, 2, 4, 8>::new(perm.clone()); 
    
    let val_mmcs = FieldMerkleTreeMmcs::<Val, <Val as Field>::Packing, _, _, 4>::new(hash.clone(), compress.clone());
    
    let ext_hasher = ExtensionHasher(hash.clone());
    let ext_compress = ExtensionCompressor(compress.clone());
    let chall_mmcs = FieldMerkleTreeMmcs::<Challenge, <Challenge as Field>::Packing, _, _, 2>::new(ext_hasher, ext_compress);

    let dft = Radix2DitParallel;
    
    let duplex = DuplexChallenger::<Val, _, 8, 4>::new(perm.clone());
    let mut challenger = ExtensionChallenger(duplex);
    
    challenger.0.observe(Val::from_canonical_u64(nonce));
    
    let fri_config = FriConfig {
        log_blowup: 1, 
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: chall_mmcs, 
    };
    
    let pcs = TwoAdicFriPcs::new(
        trace.height().trailing_zeros() as usize, 
        dft,
        val_mmcs,
        fri_config,
    );
    
    let config = StarkConfig::new(pcs);
    let air = RepeatedSquaringAir { final_val };
    
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);
    
    let proof_bytes = postcard::to_allocvec(&proof).map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;

    let payload = ProofPayload {
        commitment: final_val.as_canonical_u64(),
        valid: true,
        proof_bytes,
    };
            
    postcard::to_allocvec(&payload).map_err(|e| JsValue::from_str(&format!("Payload serialization error: {}", e)))
}

type MyPerm = Poseidon2<Val, Poseidon2ExternalMatrixHL, DiffusionMatrixGoldilocks, 8, 7>;
type MyHash = PaddingFreeSponge<MyPerm, 8, 4, 4>;
type MyCompress = TruncatedPermutation<MyPerm, 2, 4, 8>;
type MyExtHasher = ExtensionHasher<MyHash>;
type MyExtCompressor = ExtensionCompressor<MyCompress>;
type MyMmcs = FieldMerkleTreeMmcs<Val, <Val as Field>::Packing, MyHash, MyCompress, 4>;
type MyChallMmcs = FieldMerkleTreeMmcs<Challenge, <Challenge as Field>::Packing, MyExtHasher, MyExtCompressor, 2>;
type MyPcs = TwoAdicFriPcs<Val, Radix2DitParallel, MyMmcs, MyChallMmcs>;
type MyChallenger = ExtensionChallenger<DuplexChallenger<Val, MyPerm, 8, 4>>;
type MyConfig = StarkConfig<MyPcs, Challenge, MyChallenger>;

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
    
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    let compress = TruncatedPermutation::<_, 2, 4, 8>::new(perm.clone()); 
    let val_mmcs = FieldMerkleTreeMmcs::<Val, <Val as Field>::Packing, _, _, 4>::new(hash.clone(), compress.clone());
    
    let ext_hasher = ExtensionHasher(hash.clone());
    let ext_compress = ExtensionCompressor(compress.clone());
    let chall_mmcs = FieldMerkleTreeMmcs::<Challenge, <Challenge as Field>::Packing, _, _, 2>::new(ext_hasher, ext_compress);
    
    let dft = Radix2DitParallel;
    let duplex = DuplexChallenger::<Val, _, 8, 4>::new(perm.clone());
    let mut challenger = ExtensionChallenger(duplex);
    challenger.0.observe(Val::from_canonical_u64(nonce));
    
    let fri_config = FriConfig {
        log_blowup: 1, 
        num_queries: 40,
        proof_of_work_bits: 8,
        mmcs: chall_mmcs,
    };
    
    let log_n = 15; 
    
    let pcs = TwoAdicFriPcs::new(log_n, dft, val_mmcs, fri_config);
    let config = StarkConfig::new(pcs);
    
    let proof: Proof<MyConfig> = match postcard::from_bytes(&payload.proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let air = RepeatedSquaringAir { final_val: Val::from_canonical_u64(expected_commitment) };
    
    verify(&config, &air, &mut challenger, &proof, &vec![]).is_ok()
}

// ----------------------------------------------------------------------------
// 5. C FFI EXPORTS (Unchanged)
// ----------------------------------------------------------------------------

fn c_str_to_str<'a>(ptr: *const c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    unsafe {
        CStr::from_ptr(ptr).to_str().unwrap_or("")
    }
}

#[no_mangle]
pub extern "C" fn c_derive_secret_start(password: *const c_char, salt_ptr: *const u8) -> u64 {
    let pass_str = c_str_to_str(password);
    if salt_ptr.is_null() { return 0; }
    let salt = unsafe { slice::from_raw_parts(salt_ptr, 16) };
    derive_secret_start(pass_str, salt).as_canonical_u64()
}

#[no_mangle]
pub extern "C" fn c_get_commitment(password: *const c_char, salt_ptr: *const u8) -> u64 {
    let pass_str = c_str_to_str(password);
    if salt_ptr.is_null() { return 0; }
    let salt = unsafe { slice::from_raw_parts(salt_ptr, 16) };
    get_commitment(pass_str, salt)
}

#[no_mangle]
pub extern "C" fn c_prove_password(
    password: *const c_char, 
    salt_ptr: *const u8, 
    nonce: u64,
    out_len: *mut usize
) -> *mut u8 {
    let pass_str = c_str_to_str(password);
    
    if salt_ptr.is_null() { 
         unsafe { if !out_len.is_null() { *out_len = 0; } }
         return std::ptr::null_mut();
    }
    
    let salt = unsafe { slice::from_raw_parts(salt_ptr, 16) };
    
    let res = prove_password(pass_str, salt, nonce);
    
    if let Ok(proof) = res {
        let len = proof.len();
        unsafe {
            if !out_len.is_null() {
                *out_len = len;
            }
        }
        let mut boxed_slice = proof.into_boxed_slice();
        let ptr = boxed_slice.as_mut_ptr();
        std::mem::forget(boxed_slice);
        ptr
    } else {
         unsafe {
            if !out_len.is_null() {
                *out_len = 0;
            }
        }
        std::ptr::null_mut()
    }
}

#[no_mangle]
pub extern "C" fn c_verify_password_proof(
    proof_ptr: *const u8, 
    proof_len: usize,
    expected_commitment: u64, 
    nonce: u64
) -> c_int {
    if proof_ptr.is_null() {
        return 0;
    }
    let proof_slice = unsafe { slice::from_raw_parts(proof_ptr, proof_len) };
    if verify_password_proof(proof_slice, expected_commitment, nonce) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn c_free_proof(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_flow() {
        let password = "correct_horse_battery_staple";
        // 16-byte salt
        let salt = [0xabu8, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17];
        let nonce = 0;

        println!("Deriving commitment...");
        let commitment = get_commitment(password, &salt);
        println!("Commitment: {}", commitment);
        
        println!("Generating proof...");
        let res = prove_password(password, &salt, nonce);
        assert!(res.is_ok());
        let proof_bytes = res.unwrap();
        println!("Proof size: {} bytes", proof_bytes.len());
        assert!(!proof_bytes.is_empty());

        println!("Verifying proof...");
        let valid = verify_password_proof(&proof_bytes, commitment, nonce);
        assert!(valid, "Proof should verify successfully");
        
        println!("Verifying with wrong commitment...");
        let invalid = verify_password_proof(&proof_bytes, commitment + 1, nonce);
        assert!(!invalid, "Proof should fail with wrong commitment");
    }

    #[test]
    fn test_trace_generation() {
        let start = Val::from_canonical_u64(10);
        let steps = 100;
        let (trace, end) = generate_trace(start, steps);
        
        // 100 + 1 + 128 = 229 -> 256
        assert_eq!(trace.height(), 256);
        assert_eq!(trace.width(), 2);
        
        for i in 0..steps {
             assert_eq!(trace.values[i * 2 + 1], Val::one()); 
        }
        assert_eq!(trace.values[steps * 2 + 1], Val::zero());
        
        let calculated = trace.values[steps * 2];
        assert_eq!(calculated, end);
        
        assert_eq!(trace.values[(steps + 1) * 2 + 1], Val::zero());
    }
}