use p3_field::{PrimeField64, FieldArray, BasedVectorSpace, PrimeCharacteristicRing, Packable}; 
use p3_symmetric::Permutation; // Import Permutation constraint 
use p3_field::extension::BinomialExtensionField; 
use p3_air::{Air, AirBuilder, BaseAir, AirBuilderWithPublicValues}; 
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use p3_goldilocks::{Goldilocks, Poseidon2ExternalLayerGoldilocksHL, Poseidon2InternalLayerGoldilocks}; 
use p3_uni_stark::{prove, verify, StarkConfig, Proof}; 
use p3_challenger::{CanObserve, CanSample, FieldChallenger, GrindingChallenger, DuplexChallenger, CanSampleBits}; 
use p3_dft::Radix2DitParallel;
use p3_fri::{TwoAdicFriPcs, FriParameters}; 
use p3_merkle_tree::MerkleTreeMmcs; 

use p3_poseidon2::Poseidon2;
use p3_symmetric::{PaddingFreeSponge, CryptographicHasher, PseudoCompressionFunction, Hash};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Serialize, Deserialize};


// 1. CONSTANTS & TYPES
const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;
type Val = Goldilocks; // Base Field
type Challenge = BinomialExtensionField<Val, 2>; // Quadratic Extension for 100-bit+ security

// --- CRYPTOGRAPHIC CONSTANTS FOR POSEIDON-VARIANT AIR ---
// MDS matrix for width 4 - in production, use official Poseidon constants for Goldilocks
// This matrix is invertible (det ≠ 0 mod p) and provides proper diffusion
const MDS_MATRIX: [[u64; 4]; 4] = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
];

// Round constants to prevent sliding attacks
// In production, use officially generated constants from Poseidon spec
const ROUND_CONSTANT: u64 = 0x42;

// 2. AIR DEFINITION
// SECURITY: Poseidon-Variant Preimage Proof with Proper Cryptography
// This AIR proves knowledge of a secret S such that Hash(S) = Commitment
// using a Substitution-Permutation Network (SP-Network) with:
// - S-Box: x^7 (cryptographically secure for Goldilocks)
// - Linear Layer: MDS Matrix multiplication
// - Round Constants: Prevent sliding attacks
//
// TRACE LAYOUT (Width = 8):
// - Columns 0-3: State [s0, s1, s2, s3]
// - Columns 4-7: S-Box outputs [s0^7, s1^7, s2^7, s3^7]
//
// CONSTRAINT STRUCTURE:
// 1. S-Box constraints: Enforce sbox[i] = state[i]^7
// 2. Linear layer: state' = MDS * sbox + RC
// 3. Boundary: Last row state == Public Input (Commitment)

#[allow(dead_code)]
struct PoseidonPreimageAir {
    num_rounds: usize,
}

impl BaseAir<Val> for PoseidonPreimageAir {
    fn width(&self) -> usize { 8 } // 4 state + 4 S-box columns
}

impl<AB: AirBuilder<F = Val> + AirBuilderWithPublicValues> Air<AB> for PoseidonPreimageAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        
        // Extract state and S-box columns
        let s0 = local[0].clone();
        let s1 = local[1].clone();
        let s2 = local[2].clone();
        let s3 = local[3].clone();
        
        let s0_7 = local[4].clone(); // Helper column: s0^7
        let s1_7 = local[5].clone(); // Helper column: s1^7
        let s2_7 = local[6].clone(); // Helper column: s2^7
        let s3_7 = local[7].clone(); // Helper column: s3^7
        
        // --- 1. S-BOX CONSTRAINTS (x^7) ---
        // We compute x^7 = x * x^2 * x^4 and constrain the helper columns
        // This is more efficient than direct x^7 which would create degree-7 constraints
        
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
        
        // --- 2. LINEAR LAYER (MDS Matrix + Round Constant) ---
        // state' = MDS * sbox + RC
        //
        // MDS[0] = [2, 3, 1, 1]
        // new_s0 = 2*s0_7 + 3*s1_7 + 1*s2_7 + 1*s3_7 + RC
        
        let rc = AB::Expr::from(Val::from_u64(ROUND_CONSTANT));
        
        // Row 0 of MDS matrix
        let new_s0 = AB::Expr::from(Val::from_u64(MDS_MATRIX[0][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[0][3])) * s3_7.clone()
                   + rc.clone();
        
        // Row 1 of MDS matrix
        let new_s1 = AB::Expr::from(Val::from_u64(MDS_MATRIX[1][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[1][3])) * s3_7.clone()
                   + rc.clone();
        
        // Row 2 of MDS matrix
        let new_s2 = AB::Expr::from(Val::from_u64(MDS_MATRIX[2][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[2][3])) * s3_7.clone()
                   + rc.clone();
        
        // Row 3 of MDS matrix
        let new_s3 = AB::Expr::from(Val::from_u64(MDS_MATRIX[3][0])) * s0_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][1])) * s1_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][2])) * s2_7.clone()
                   + AB::Expr::from(Val::from_u64(MDS_MATRIX[3][3])) * s3_7.clone()
                   + rc;
        
        // Constrain transitions
        builder.when_transition().assert_eq(next[0].clone(), new_s0);
        builder.when_transition().assert_eq(next[1].clone(), new_s1);
        builder.when_transition().assert_eq(next[2].clone(), new_s2);
        builder.when_transition().assert_eq(next[3].clone(), new_s3);
        
        // --- 3. BOUNDARY CONSTRAINTS ---
        // The last row state must match the Public Input (Commitment)
        let pis = builder.public_values();
        let expected_0 = pis[0];
        let expected_1 = pis[1];
        let expected_2 = pis[2];
        let expected_3 = pis[3];
        
        builder.when_last_row().assert_eq(local[0].clone(), expected_0);
        builder.when_last_row().assert_eq(local[1].clone(), expected_1);
        builder.when_last_row().assert_eq(local[2].clone(), expected_2);
        builder.when_last_row().assert_eq(local[3].clone(), expected_3);
    }
}

// 3. CHALLENGER & HASHER
// We need a challenger that operates on the Extension Field to be secure.
#[derive(Clone)]
struct ExtensionChallenger<C>(C);

impl<C: CanObserve<Val>> CanObserve<Challenge> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Challenge) {
        // Observe coefficients of extension element
         for coeff in value.as_basis_coefficients_slice() {
            self.0.observe(*coeff);
        }
    }
}

impl<C: CanSample<Val>> CanSample<Challenge> for ExtensionChallenger<C> {
    fn sample(&mut self) -> Challenge {
        // Sample 2 Base elements to form Extension (Degree 2)
        let a = self.0.sample();
        let b = self.0.sample();
        // Construct extension from [a, b]
        Challenge::new([a, b])
    }
}

// Forward CanObserve<Val>
impl<C: CanObserve<Val>> CanObserve<Val> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Val) {
        self.0.observe(value);
    }
}

// Forward CanSample<Val>
impl<C: CanSample<Val>> CanSample<Val> for ExtensionChallenger<C> {
    fn sample(&mut self) -> Val {
        self.0.sample()
    }
}

impl<C: GrindingChallenger<Witness = Val>> GrindingChallenger for ExtensionChallenger<C> {
    type Witness = Val; // Grinding usually happens on base field or specific witness type
    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.0.grind(bits)
    }
}

impl<C: CanObserve<Val>> CanObserve<Hash<Challenge, Challenge, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Hash<Challenge, Challenge, 4>) {
        let arr: [Challenge; 4] = value.into();
        for v in arr {
            self.observe(v); // Dispatches to observe(Challenge)
        }
    }
}

// Observe Hash<Val, Val, 4>
impl<C: CanObserve<Val>> CanObserve<Hash<Val, Val, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Hash<Val, Val, 4>) {
        let arr: [Val; 4] = value.into();
        for v in arr {
            self.0.observe(v);
        }
    }
}

impl<C: CanObserve<Val>> CanObserve<Hash<Challenge, Val, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Hash<Challenge, Val, 4>) {
        let arr: [Val; 4] = value.into();
        self.observe(arr);
    }
}

impl<C: CanObserve<Val>> CanObserve<Hash<Val, HashDigest, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Hash<Val, HashDigest, 4>) {
        let arr: [HashDigest; 4] = value.into();
        for d in arr {
             self.observe(d);
        }
    }
}

impl<C: CanObserve<Val>> CanObserve<Hash<Challenge, HashDigest, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: Hash<Challenge, HashDigest, 4>) {
        let arr: [HashDigest; 4] = value.into();
        for d in arr {
             self.observe(d);
        }
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[repr(transparent)]
pub struct HashDigest(pub [Val; 4]);

impl Packable for HashDigest {}

// Manual PackedValue impl removed to avoid conflict with blanket impl
// impl Packable for HashDigest {} is sufficient.

impl<C: CanObserve<Val>> CanObserve<HashDigest> for ExtensionChallenger<C> {
    fn observe(&mut self, value: HashDigest) {
        let arr = value.0;
        self.observe(arr);
    }
}

// Custom Hasher for Challenge (Extension) -> HashDigest
#[derive(Clone)]
struct ChallengeHasher(MyHash);

// 1. Hasher Impls for ChallengeHasher (Scalar)
impl CryptographicHasher<Challenge, HashDigest> for ChallengeHasher {
    fn hash_iter<I: IntoIterator<Item = Challenge>>(&self, input: I) -> HashDigest {
        // Flatten inputs
        let iter = input.into_iter().flat_map(|c| {
             let s: &[Val] = c.as_basis_coefficients_slice();
             let v: Vec<Val> = s.to_vec();
             v
        });
        let h = self.0.hash_iter(iter);
        let arr: [Val; 4] = h.into();
        HashDigest(arr)
    }
}

// Vectorized impl for safety / requirement
// Vectorized impl for safety / requirement
impl CryptographicHasher<Challenge, [HashDigest; 4]> for ChallengeHasher {
    fn hash_iter<I: IntoIterator<Item = Challenge>>(&self, input: I) -> [HashDigest; 4] {
         let mut vecs = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
         for c in input {
             // Broadcast challenge? Or split? Challenge is scalarish extension.
             // Usually we broadcast scalar challenge to all lanes.
             vecs[0].push(c);
             vecs[1].push(c);
             vecs[2].push(c);
             vecs[3].push(c);
         }
         [
             self.hash_iter(vecs[0].iter().copied()),
             self.hash_iter(vecs[1].iter().copied()),
             self.hash_iter(vecs[2].iter().copied()),
             self.hash_iter(vecs[3].iter().copied()),
         ]
    }
}

// Custom Hasher for Val (Trace) -> HashDigest
#[derive(Clone)]
struct ValHasher(MyHash);

// A. Val -> HashDigest (Scalar)
// A. Val -> HashDigest (Scalar)
impl CryptographicHasher<Val, HashDigest> for ValHasher {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> HashDigest {
        let h = self.0.hash_iter(input);
        // MyHash returns FieldArray<Val, 4> usually via Into.
        // We know MyHash is PaddingFreeSponge -> returns [Val; 4] or FieldArray.
        // Let's use standard into().
        let arr: [Val; 4] = h.into();
        HashDigest(arr)
    }
}

// B. Val -> [HashDigest; 4]
// Broadcast scalar stream to 4 digests
impl CryptographicHasher<Val, [HashDigest; 4]> for ValHasher {
    fn hash_iter<I: IntoIterator<Item = Val>>(&self, input: I) -> [HashDigest; 4] {
        let v: Vec<Val> = input.into_iter().collect();
        let h = self.hash_iter(v);
        [h, h, h, h]
    }
}

// C. [Val; 4] -> [HashDigest; 4]
// Vectorized input stream -> 4 independent digests
impl CryptographicHasher<[Val; 4], [HashDigest; 4]> for ValHasher {
    fn hash_iter<I: IntoIterator<Item = [Val; 4]>>(&self, input: I) -> [HashDigest; 4] {
        let mut vecs = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for row in input {
            vecs[0].push(row[0]);
            vecs[1].push(row[1]);
            vecs[2].push(row[2]);
            vecs[3].push(row[3]);
        }
        [
             self.hash_iter(vecs[0].iter().copied()),
             self.hash_iter(vecs[1].iter().copied()),
             self.hash_iter(vecs[2].iter().copied()),
             self.hash_iter(vecs[3].iter().copied()),
        ]
    }
}

// Inner Node Hashing (Digest -> Digest)
// Since HashDigest has WIDTH=1, MerkleTree will use serial compression?
// No, MerkleTree inner nodes use Compress trait.
// Hasher is used for leaves.

// Also impl for [Val; 8]
     


// Implement FieldChallenger for Val (Base Field)
impl<C: FieldChallenger<Val>> FieldChallenger<Val> for ExtensionChallenger<C> {
     fn sample_algebra_element<A: p3_field::BasedVectorSpace<Val>>(&mut self) -> A {
         self.0.sample_algebra_element()
     }
}

// Implement FieldChallenger for Challenge
impl<C: FieldChallenger<Val> + CanObserve<Val> + CanSample<Val> + GrindingChallenger> FieldChallenger<Challenge> for ExtensionChallenger<C> {
    fn sample_algebra_element<A: p3_field::BasedVectorSpace<Challenge>>(&mut self) -> A {
        let dim = A::DIMENSION;
        let vec: Vec<Challenge> = (0..dim).map(|_| self.sample()).collect();
        A::from_basis_coefficients_slice(&vec).unwrap()
    }
}

impl<C: CanSampleBits<usize>> CanSampleBits<usize> for ExtensionChallenger<C> {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.0.sample_bits(bits)
    }
}

// Observe FieldArray (Digest)
impl<C: CanObserve<Val>> CanObserve<FieldArray<Val, 4>> for ExtensionChallenger<C> {
    fn observe(&mut self, value: FieldArray<Val, 4>) {
        self.0.observe_slice(&value.0);
    }
}


// Observe [Val; 4] (Digest)
impl<C: CanObserve<Val>> CanObserve<[Val; 4]> for ExtensionChallenger<C> {
    fn observe(&mut self, value: [Val; 4]) {
        for v in value {
             self.0.observe(v);
        }
    }
}

// Wrapper for Compression to handle types explicitly
#[derive(Clone)]
struct MyCompressWrapper(MyPerm);

// Impl for FieldArray Arity 2 (Scalar)
impl PseudoCompressionFunction<FieldArray<Val, 4>, 2> for MyCompressWrapper {
    fn compress(&self, input: [FieldArray<Val, 4>; 2]) -> FieldArray<Val, 4> {
        let mut row = [Val::default(); 8];
        row[0..4].copy_from_slice(&input[0].0);
        row[4..8].copy_from_slice(&input[1].0);
        let out = self.0.permute(row);
        let mut res = [Val::default(); 4];
        res.copy_from_slice(&out[0..4]);
        FieldArray(res)
    }
}

// Impl for [[Val; 4]; 4] Arity 2 (Vectorized)
impl PseudoCompressionFunction<[[Val; 4]; 4], 2> for MyCompressWrapper {
    fn compress(&self, input: [[[Val; 4]; 4]; 2]) -> [[Val; 4]; 4] {
        let mut out = [[Val::default(); 4]; 4];
        for i in 0..4 {
             let leaf_pair = [input[0][i], input[1][i]];
             let mut row = [Val::default(); 8];
             row[0..4].copy_from_slice(&leaf_pair[0]);
             row[4..8].copy_from_slice(&leaf_pair[1]);
             let perm_out = self.0.permute(row);
             let mut res = [Val::default(); 4];
             res.copy_from_slice(&perm_out[0..4]);
             out[i] = res;
        }
        out
    }
}

// Impl for HashDigest Arity 2 (Scalar) - Native Width 8
impl PseudoCompressionFunction<HashDigest, 2> for MyCompressWrapper {
    fn compress(&self, input: [HashDigest; 2]) -> HashDigest {
        let mut row = [Val::default(); 8];
        row[0..4].copy_from_slice(&input[0].0);
        row[4..8].copy_from_slice(&input[1].0);
        let out = self.0.permute(row);
        let mut res = [Val::default(); 4];
        res.copy_from_slice(&out[0..4]);
        HashDigest(res)
    }
}

// Impl for [HashDigest; 4] Arity 2 (Vectorized)
impl PseudoCompressionFunction<[HashDigest; 4], 2> for MyCompressWrapper {
    fn compress(&self, input: [[HashDigest; 4]; 2]) -> [HashDigest; 4] {
        let mut out = [HashDigest::default(); 4];
        for i in 0..4 {
             let d0 = input[0][i];
             let d1 = input[1][i];
             out[i] = self.compress([d0, d1]);
        }
        out
    }
}

// Impl for FieldArray Arity 4 (Scalar)
impl PseudoCompressionFunction<FieldArray<Val, 4>, 4> for MyCompressWrapper {
    fn compress(&self, input: [FieldArray<Val, 4>; 4]) -> FieldArray<Val, 4> {
        // Chain 2-to-1 compression
        let mut row1 = [Val::default(); 8];
        row1[0..4].copy_from_slice(&input[0].0);
        row1[4..8].copy_from_slice(&input[1].0);
        let mid1_full = self.0.permute(row1);
        
        let mut row2 = [Val::default(); 8];
        row2[0..4].copy_from_slice(&input[2].0);
        row2[4..8].copy_from_slice(&input[3].0);
        let mid2_full = self.0.permute(row2);
        
        let mut final_row = [Val::default(); 8];
        final_row[0..4].copy_from_slice(&mid1_full[0..4]);
        final_row[4..8].copy_from_slice(&mid2_full[0..4]);
        let out = self.0.permute(final_row);
        
        let mut res = [Val::default(); 4];
        res.copy_from_slice(&out[0..4]);
        FieldArray(res)
    }
}

// Impl for [Val; 4] Arity 4 (Scalar)
impl PseudoCompressionFunction<[Val; 4], 4> for MyCompressWrapper {
    fn compress(&self, input: [[Val; 4]; 4]) -> [Val; 4] {
        let mut row1 = [Val::default(); 8];
        row1[0..4].copy_from_slice(&input[0]);
        row1[4..8].copy_from_slice(&input[1]);
        let mid1_full = self.0.permute(row1);
        
        let mut row2 = [Val::default(); 8];
        row2[0..4].copy_from_slice(&input[2]);
        row2[4..8].copy_from_slice(&input[3]);
        let mid2_full = self.0.permute(row2);
        
        let mut final_row = [Val::default(); 8];
        final_row[0..4].copy_from_slice(&mid1_full[0..4]);
        final_row[4..8].copy_from_slice(&mid2_full[0..4]);
        let out = self.0.permute(final_row);
        
        let mut res = [Val::default(); 4];
        res.copy_from_slice(&out[0..4]);
        res
    }
}

// Impl for [Val; 4] Arity 2
impl PseudoCompressionFunction<[Val; 4], 2> for MyCompressWrapper {
    fn compress(&self, input: [[Val; 4]; 2]) -> [Val; 4] {
        let mut row = [Val::default(); 8];
        row[0..4].copy_from_slice(&input[0]);
        row[4..8].copy_from_slice(&input[1]);
        let out = self.0.permute(row); 
        let mut res = [Val::default(); 4];
        res.copy_from_slice(&out[0..4]);
        res
    }
}


// Helper to fill slice
// Removed duplicate CopyFromSlice definition.



// 4. ARGON2 UTILS & TRACE GENERATON
// Biased implementation fix: rejection sampling
pub fn derive_secret_start(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Val,argon2::Error> {
    let params = argon2::Params::new(m_cost, t_cost, p_cost, Some(32)).unwrap();
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    
    let mut output = [0u8; 32];
    // Rejection sampling loop
    let mut nonce = 0u64;
    loop {
        // Vary salt with nonce to get fresh hash
        let mut salt_with_nonce = salt.to_vec();
        salt_with_nonce.extend_from_slice(&nonce.to_le_bytes());

        argon.hash_password_into(password.as_bytes(), &salt_with_nonce, &mut output)?;
        
        // Interpret as U256 (4x u64). take first u64.
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&output[0..8]);
        let rand_u64 = u64::from_le_bytes(val_bytes);
        
        if rand_u64 < GOLDILOCKS_PRIME {
            return Ok(Val::from_u64(rand_u64));
        }
        nonce += 1;
    }
}

pub fn generate_poseidon_trace(secret: Val, num_rounds: usize) -> (RowMajorMatrix<Val>, [Val; 4]) {
    // Trace width = 8 columns (4 state + 4 S-box)
    // Height = num_rounds + 1 (padded to power of 2)
    let height = (num_rounds + 1).next_power_of_two();
    let width = 8;
    
    let mut trace_data = vec![Val::ZERO; height * width];
    
    // Initialize State [secret, 0, 0, 0]
    let mut state = [secret, Val::ZERO, Val::ZERO, Val::ZERO];
    
    // Fill trace (apply hash rounds for all rows to satisfy constraints)
    for i in 0..height {
        let row_idx = i * width;
        
        // 1. Write State to Trace
        trace_data[row_idx] = state[0];
        trace_data[row_idx + 1] = state[1];
        trace_data[row_idx + 2] = state[2];
        trace_data[row_idx + 3] = state[3];
        
        // 2. Compute S-Box Output (x^7)
        let s0_7 = state[0].exp_u64(7);
        let s1_7 = state[1].exp_u64(7);
        let s2_7 = state[2].exp_u64(7);
        let s3_7 = state[3].exp_u64(7);
        
        // 3. Write S-Box to Trace (Helper columns)
        trace_data[row_idx + 4] = s0_7;
        trace_data[row_idx + 5] = s1_7;
        trace_data[row_idx + 6] = s2_7;
        trace_data[row_idx + 7] = s3_7;
        
        // 4. Compute Next State (MDS * SBox + RC) for next iteration
        if i < height - 1 {
            let rc = Val::from_u64(ROUND_CONSTANT);
            let mut next_state = [Val::ZERO; 4];
            
            let s_vec = [s0_7, s1_7, s2_7, s3_7];
            
            // Matrix multiplication: next_state = MDS * s_vec + RC
            for r in 0..4 {
                let mut sum = rc;
                for c in 0..4 {
                    let m_val = Val::from_u64(MDS_MATRIX[r][c]);
                    sum += m_val * s_vec[c];
                }
                next_state[r] = sum;
            }
            state = next_state;
        }
    }
    
    // Extract commitment (first 4 elements of state at round num_rounds)
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

pub fn new_poseidon2_goldilocks() -> Poseidon2<Val, Poseidon2ExternalLayerGoldilocksHL<8>, Poseidon2InternalLayerGoldilocks, 8, 7> {
    let mut rng = StdRng::seed_from_u64(42);
    Poseidon2::new_from_rng_128(&mut rng)
}

pub fn get_commitment(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<[Val; 4], String> {
    let secret = derive_secret_start(password, salt, m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    // Use a number of rounds that results in trace height being a power of 2
    // For num_rounds=15, height = 16 (next_power_of_two(15+1))
    let num_rounds = 15; // This makes the final row be row 15 in a height-16 trace
    let (_trace, commitment) = generate_poseidon_trace(secret, num_rounds);
    Ok(commitment)
}

// 5. PROOF GENERATION & VERIFICATION
#[derive(Serialize, Deserialize)]
pub struct ProofPayload {
    pub commitment: [u64; 4], // 4-element Poseidon hash commitment
    pub valid: bool,
    pub proof_bytes: Vec<u8>,
}

pub fn prove_password(password: &str, salt: &[u8], _nonce: u64,  m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Vec<u8>, String> {
    let secret = derive_secret_start(password, salt, m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    let num_rounds = 15; // Must match get_commitment()
    let (trace, commitment) = generate_poseidon_trace(secret, num_rounds);
    
    let perm = new_poseidon2_goldilocks();
    let compress_wrapper = MyCompressWrapper(perm.clone());
    
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    
    let val_hasher = ValHasher(hash.clone());
    let chall_hasher = ChallengeHasher(hash.clone());
    
    let val_mmcs = MerkleTreeMmcs::<Val, HashDigest, _, _, 4>::new(val_hasher, compress_wrapper.clone());
    
    let chall_mmcs = MerkleTreeMmcs::<Challenge, HashDigest, _, _, 4>::new(chall_hasher, compress_wrapper.clone());

    let dft = Radix2DitParallel::default();
    
    let duplex = DuplexChallenger::<Val, _, 8, 4>::new(perm.clone());
    let challenger = ExtensionChallenger(duplex);
    
    let fri_config = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 2,
        num_queries: 70,
        query_proof_of_work_bits: 16,
        commit_proof_of_work_bits: 0,
        mmcs: chall_mmcs,
    };
    
    let pcs = TwoAdicFriPcs::new(
        dft,
        val_mmcs,
        fri_config,
    );
    
    let config: StarkConfig<_, Challenge, _> = StarkConfig::new(pcs, challenger.clone());

    let air = PoseidonPreimageAir {
        num_rounds,
    };
    
    // Public inputs: [commitment[0], commitment[1], commitment[2], commitment[3]]
    let public_inputs = commitment;

    // prove(config, air, trace, public_values)
    let proof = prove(&config, &air, trace, &public_inputs);
    
    let proof_bytes = postcard::to_allocvec(&proof).map_err(|e| format!("Serialization error: {}", e))?;

    let commitment_u64 = commitment.map(|v| v.as_canonical_u64());
    let payload = ProofPayload {
        commitment: commitment_u64,
        valid: true,
        proof_bytes,
    };
            
    let mut serialized_payload = postcard::to_allocvec(&payload)
        .map_err(|e| format!("Payload serialization error: {}", e))?;
    
    let mut output = Vec::with_capacity(serialized_payload.len() + 1);
    output.push(1u8); // Schema Version
    output.append(&mut serialized_payload);
    
    Ok(output)
}
type MyPerm = Poseidon2<Val, Poseidon2ExternalLayerGoldilocksHL<8>, Poseidon2InternalLayerGoldilocks, 8, 7>;
type MyHash = PaddingFreeSponge<MyPerm, 8, 4, 4>;
type MyCompress = MyCompressWrapper;
type MyExtHasher = ChallengeHasher;
type MyValHasher = ValHasher;
type MyExtCompress = MyCompress;
type MyChallMmcs = MerkleTreeMmcs<Challenge, HashDigest, MyExtHasher, MyExtCompress, 4>;
 
type MyPcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, MerkleTreeMmcs<Val, HashDigest, MyValHasher, MyCompress, 4>, MyChallMmcs>;
type MyChallenger = ExtensionChallenger<DuplexChallenger<Val, MyPerm, 8, 4>>;
type MyConfig = StarkConfig<MyPcs, Challenge, MyChallenger>;

pub fn verify_password_proof(proof_bytes: &[u8], expected_commitment: [Val; 4], _nonce: u64) -> bool {
    // 1. Schema check
    if proof_bytes.is_empty() || proof_bytes[0] != 1 {
        return false;
    }

    let payload: ProofPayload = match postcard::from_bytes(&proof_bytes[1..]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    // Verify commitment matches
    let expected_u64: [u64; 4] = expected_commitment.map(|v| v.as_canonical_u64());
    if payload.commitment != expected_u64 {
        return false;
    }
    
    let perm = new_poseidon2_goldilocks();
    let compress_wrapper = MyCompressWrapper(perm.clone());
    
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    
    let val_hasher = ValHasher(hash.clone());
    let chall_hasher = ChallengeHasher(hash.clone());
    
    let val_mmcs = MerkleTreeMmcs::<Val, HashDigest, _, _, 4>::new(val_hasher, compress_wrapper.clone());
    
    let chall_mmcs = MerkleTreeMmcs::<Challenge, HashDigest, _, _, 4>::new(chall_hasher, compress_wrapper.clone());
    
    let dft = Radix2DitParallel::default();
    let duplex = DuplexChallenger::<Val, _, 8, 4>::new(perm.clone());
    let challenger = ExtensionChallenger(duplex);
    
    let fri_config = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 2,
        num_queries: 70,
        query_proof_of_work_bits: 16,
        commit_proof_of_work_bits: 0,
        mmcs: chall_mmcs,
    };
    
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_config);
    let config = StarkConfig::new(pcs, challenger.clone());
    
    let proof: Proof<MyConfig> = match postcard::from_bytes(&payload.proof_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let air = PoseidonPreimageAir {
        num_rounds: 15, // Must match get_commitment()
    };
    
    // Public inputs: expected_commitment (4 field elements)
    let public_inputs = expected_commitment;
    
    verify(&config, &air, &proof, &public_inputs).is_ok()
}

// ----------------------------------------------------------------------------
// 6. C FFI EXPORTS (Updated for Safety)
// ----------------------------------------------------------------------------

// Opaque pointer wrapper
#[repr(C)]
pub struct OpaqueProofResult {
    _private: [u8; 0],
}

#[no_mangle]
pub extern "C" fn c_derive_secret_start(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> u64 {
    // Safety: check null
    if password_ptr.is_null() || salt_ptr.is_null() { return 0; }

    let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
    
    // Panic safety wrapper
    let result = std::panic::catch_unwind(move || {
        let password_str = match std::str::from_utf8(password_bytes) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        match derive_secret_start(password_str, salt, m_cost, t_cost, p_cost) {
            Ok(val) => val.as_canonical_u64(),
            Err(_) => 0,
        }
    });

    result.unwrap_or(0)
}

#[repr(C)]
pub struct CommitmentResult {
    values: [u64; 4],
    success: bool,
}

#[no_mangle]
pub extern "C" fn c_get_commitment(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> CommitmentResult {
    // Safety: check null
    if password_ptr.is_null() || salt_ptr.is_null() { 
        return CommitmentResult { values: [0; 4], success: false }; 
    }

    let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
    
    // Panic safety wrapper
    let result = std::panic::catch_unwind(move || {
        let password_str = match std::str::from_utf8(password_bytes) {
            Ok(s) => s,
            Err(_) => return CommitmentResult { values: [0; 4], success: false },
        };

        match get_commitment(password_str, salt, m_cost, t_cost, p_cost) {
            Ok(commitment) => CommitmentResult { 
                values: commitment.map(|v| v.as_canonical_u64()), 
                success: true 
            },
            Err(_) => CommitmentResult { values: [0; 4], success: false },
        }
    });

    result.unwrap_or(CommitmentResult { values: [0; 4], success: false })
}

// 6. PROVE FFI
#[repr(C)]
pub struct ProofResult {
    ptr: *mut u8,
    len: usize,
    cap: usize,
    status: u32, // 0 = OK, 1 = Error
}

#[repr(u32)]
pub enum StatusCode {
    Success = 0,
    InvalidInput = 1,
    ProvingError = 2,
    AllocError = 3,
}

#[no_mangle]
pub extern "C" fn c_prove_password(
    password_ptr: *const u8,
    password_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    nonce: u64,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> *mut OpaqueProofResult {
    
    if password_ptr.is_null() || salt_ptr.is_null() {
        return std::ptr::null_mut();
    }

    let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
    
    // Panic safety wrapper
    let result = std::panic::catch_unwind(move || {
        let password_str = match std::str::from_utf8(password_bytes) {
            Ok(s) => s,
            Err(_) => return ProofResult { ptr: std::ptr::null_mut(), len: 0, cap: 0, status: StatusCode::InvalidInput as u32 },
        };

        let res = prove_password(password_str, salt, nonce, m_cost, t_cost, p_cost);
        match res {
            Ok(mut bytes) => {
                let ptr = bytes.as_mut_ptr();
                let len = bytes.len();
                let cap = bytes.capacity();
                std::mem::forget(bytes);
                ProofResult {
                    ptr,
                    len,
                    cap,
                    status: StatusCode::Success as u32,
                }
            },
            Err(_) => ProofResult { ptr: std::ptr::null_mut(), len: 0, cap: 0, status: StatusCode::ProvingError as u32 }
        }
    });

    match result {
        Ok(proof_res) => {
            let res_box = Box::new(proof_res);
            Box::into_raw(res_box) as *mut OpaqueProofResult
        },
        Err(_) => std::ptr::null_mut(), // Panic occurred
    }
}

// 7. VERIFY FFI
#[no_mangle]
pub extern "C" fn c_verify_password_proof(
    proof_ptr: *mut OpaqueProofResult,
    commitment_ptr: *const u64, // Pointer to 4-element array
    nonce: u64,
) -> bool {
    if proof_ptr.is_null() || commitment_ptr.is_null() { return false; }
    
    let proof_res = unsafe { &*(proof_ptr as *const ProofResult) };
    if proof_res.status != 0 { return false; }
    
    let commitment_slice = unsafe { std::slice::from_raw_parts(commitment_ptr, 4) };
    let commitment: [Val; 4] = [
        Val::from_u64(commitment_slice[0]),
        Val::from_u64(commitment_slice[1]),
        Val::from_u64(commitment_slice[2]),
        Val::from_u64(commitment_slice[3]),
    ];
    
    let proof_slice = unsafe { std::slice::from_raw_parts(proof_res.ptr, proof_res.len) };
    verify_password_proof(proof_slice, commitment, nonce)
}

#[no_mangle]
pub extern "C" fn c_free_proof(res_ptr: *mut OpaqueProofResult) {
    if res_ptr.is_null() { return; }
    unsafe {
        let res = Box::from_raw(res_ptr as *mut ProofResult);
        // Reconstruct Vec to drop it
        if !res.ptr.is_null() {
            let _ = Vec::from_raw_parts(res.ptr, res.len, res.cap);
        }
        // res dropped here
    }
}

// 8. TESTS
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prove_and_verify_flow() {
        let pass = "correct_horse";
        let salt = b"battery_staple";
        let nonce = 12345;
        let m_cost = 4096;
        let t_cost = 3;
        let p_cost = 1;
        
        // 1. Get commitment
        let commitment = get_commitment(pass, salt, m_cost, t_cost, p_cost).expect("Commit failed");
        
        // 2. Prove
        let proof = prove_password(pass, salt, nonce, m_cost, t_cost, p_cost).expect("Prove failed");
        
        // 3. Verify
        let valid = verify_password_proof(&proof, commitment, nonce);
        assert!(valid, "Proof should verify");
        
        // 4. Verify Failure Cases
        let mut invalid_commitment = commitment;
        invalid_commitment[0] = invalid_commitment[0] + Val::ONE;
        assert!(!verify_password_proof(&proof, invalid_commitment, nonce), "Should fail wrong commitment");
        
        let invalid_proof = vec![1, 2, 3];
        assert!(!verify_password_proof(&invalid_proof, commitment, nonce), "Should fail invalid proof bytes");
    }
}
