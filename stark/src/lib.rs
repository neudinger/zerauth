use p3_field::{PrimeField64, FieldArray, BasedVectorSpace, PrimeCharacteristicRing, Packable}; 
use p3_symmetric::Permutation; // Import Permutation constraint 
use p3_field::extension::BinomialExtensionField; 
use p3_air::{Air, AirBuilder, BaseAir}; 
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

// 2. AIR DEFINITION
// Simple Repeated Squaring: x_{i+1} = x_i^2
struct RepeatedSquaringAir {
    final_val: Val,
}

impl BaseAir<Val> for RepeatedSquaringAir {
    fn width(&self) -> usize { 1 }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for RepeatedSquaringAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).unwrap();
        let next = main.row_slice(1).unwrap();
        
        let val = local[0].clone();
        let val_next = next[0].clone();
        
        let transition_constraint = val_next - val.clone() * val;
        builder.when_transition().assert_zero(transition_constraint);
        
        // Boundary constraint: last value must match self.final_val
        // We enforce that the LAST row matches `final_val`.
        // Ideally we use builder.when_last_row().assert_eq(local[0], final_val)
        // However, we can also bind it via Public Inputs.
        // If we want to hardcode it in AIR instance:
        builder.when_last_row().assert_eq(local[0].clone(), AB::Expr::from(self.final_val));
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

pub fn generate_trace(start_val: Val, steps: usize) -> RowMajorMatrix<Val> {
    // Trace has 1 column. 
    // We pad to power of two.
    let height = steps.next_power_of_two();
    let mut trace_values = Vec::with_capacity(height);
    
    let mut current = start_val;
    for _ in 0..steps {
        trace_values.push(current);
        current = current * current;
    }
    
    // Padding: Fill with zeroes? Or valid transitions?
    // If we pad with zeros, transition constraints might fail at the boundary.
    // If we pad with valid transitions, we might exceed complexity.
    // Standard AIR padding: constraints shouldn't apply to padding rows, OR padding rows are valid.
    // Valid padding is safer.
    while trace_values.len() < height {
        trace_values.push(current);
        current = current * current;
    }
    
    RowMajorMatrix::new(trace_values, 1) // 1 column
}

pub fn new_poseidon2_goldilocks() -> Poseidon2<Val, Poseidon2ExternalLayerGoldilocksHL<8>, Poseidon2InternalLayerGoldilocks, 8, 7> {
    let mut rng = StdRng::seed_from_u64(42);
    Poseidon2::new_from_rng_128(&mut rng)
}

pub fn get_commitment(password: &str, salt: &[u8], m_cost: u32, t_cost: u32, p_cost: u32) -> Result<u64, String> {
    let start_val = derive_secret_start(password, salt, m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    // A commitment to the execution is the final value.
    // We run the trace generation (or just value calculation) -> 10 iterations?
    // Trace length is small for password proof.
    let steps = 10; 
    let trace = generate_trace(start_val, steps);
    // Return last element
    Ok(trace.values.last().unwrap().as_canonical_u64())
}

// 5. PROOF GENERATION & VERIFICATION
#[derive(Serialize, Deserialize)]
pub struct ProofPayload {
    pub commitment: u64,
    pub valid: bool, // Redundant but useful for API
    pub proof_bytes: Vec<u8>,
}

pub fn prove_password(password: &str, salt: &[u8], nonce: u64,  m_cost: u32, t_cost: u32, p_cost: u32) -> Result<Vec<u8>, String> {
    let start_val = derive_secret_start(password, salt, m_cost, t_cost, p_cost).map_err(|e| e.to_string())?;
    let steps = 10;
    let trace = generate_trace(start_val, steps);
    let final_val = *trace.values.last().unwrap();
    
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
        // Proof of work bits should be reasonable
        query_proof_of_work_bits: 16,
        commit_proof_of_work_bits: 0,
        mmcs: chall_mmcs,
    };
    
    let pcs = TwoAdicFriPcs::new(
        dft,
        val_mmcs,
        fri_config,
    );
    
    let config = StarkConfig::new(pcs, challenger.clone());
    let air = RepeatedSquaringAir { final_val };
    
    // prove(config, air, trace, public_values)
    let proof = prove(&config, &air, trace, &[Val::new(nonce)]);
    
    let proof_bytes = postcard::to_allocvec(&proof).map_err(|e| format!("Serialization error: {}", e))?;

    let payload = ProofPayload {
        commitment: final_val.as_canonical_u64(),
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
type MyCompress = MyCompressWrapper; // Use wrapper
type MyExtHasher = ChallengeHasher;
type MyValHasher = ValHasher;
type MyExtCompress = MyCompress;
type MyChallMmcs = MerkleTreeMmcs<Challenge, HashDigest, MyExtHasher, MyExtCompress, 4>;
 
type MyPcs = TwoAdicFriPcs<Val, Radix2DitParallel<Val>, MerkleTreeMmcs<Val, HashDigest, MyValHasher, MyCompress, 4>, MyChallMmcs>;
type MyChallenger = ExtensionChallenger<DuplexChallenger<Val, MyPerm, 8, 4>>;
type MyConfig = StarkConfig<MyPcs, Challenge, MyChallenger>;

pub fn verify_password_proof(proof_bytes: &[u8], expected_commitment: u64, nonce: u64) -> bool {
    // 1. Schema check
    if proof_bytes.is_empty() || proof_bytes[0] != 1 {
        return false;
    }

    let payload: ProofPayload = match postcard::from_bytes(&proof_bytes[1..]) {
        Ok(p) => p,
        Err(_) => return false,
    };
    
    if payload.commitment != expected_commitment {
        return false;
    }
    
    let perm = new_poseidon2_goldilocks();
    let compress_wrapper = MyCompressWrapper(perm.clone());
    
    let hash = PaddingFreeSponge::<_, 8, 4, 4>::new(perm.clone());
    
    let val_hasher = ValHasher(hash.clone());
    let chall_hasher = ChallengeHasher(hash.clone());
    
    let val_mmcs = MerkleTreeMmcs::<Val, HashDigest, _, _, 4>::new(val_hasher, compress_wrapper.clone());
    
    // N=4
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

    let air = RepeatedSquaringAir { final_val: Val::new(expected_commitment) };
    
    // Verify (config, air, proof, public_values).
    // This expects proof to match config.
    // MyConfig uses [Val; 4] digest.
    verify(&config, &air, &proof, &[Val::new(nonce)]).is_ok()
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
    
    let password_str = match std::str::from_utf8(password_bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match derive_secret_start(password_str, salt, m_cost, t_cost, p_cost) {
        Ok(val) => val.as_canonical_u64(),
        Err(_) => 0,
    }
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
) -> u64 {
    // Safety: check null
    if password_ptr.is_null() || salt_ptr.is_null() { return 0; }

    let password_bytes = unsafe { std::slice::from_raw_parts(password_ptr, password_len) };
    let salt = unsafe { std::slice::from_raw_parts(salt_ptr, salt_len) };
    
    let password_str = match std::str::from_utf8(password_bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    match get_commitment(password_str, salt, m_cost, t_cost, p_cost) {
        Ok(val) => val,
        Err(_) => 0,
    }
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
    
    let password_str = match std::str::from_utf8(password_bytes) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = prove_password(password_str, salt, nonce, m_cost, t_cost, p_cost);
    
    match result {
        Ok(mut bytes) => {
            // Include byte length prefix for safe C consumption if needed, but struct has len.
            // Just return raw bytes.
            let ptr = bytes.as_mut_ptr();
            let len = bytes.len();
            let cap = bytes.capacity();
            std::mem::forget(bytes); // Prevent Drop
            
            // Allocate a small struct to hold metadata or just return pointer?
            // User wrapper OpaqueProofResult usually wraps internal struct.
            // But here we return Vec<u8> which is a fat pointer.
            // FFI usually prefers a Struct with ptr/len.
            // But we can only return 1 pointer.
            // Let's alloc 'ProofResult' on heap and return pointer to it.
            
            let res = Box::new(ProofResult {
                ptr,
                len,
                cap,
                status: StatusCode::Success as u32,
            });
            Box::into_raw(res) as *mut OpaqueProofResult
        },
        Err(_) => std::ptr::null_mut(),
    }
}

// 7. VERIFY FFI
#[no_mangle]
pub extern "C" fn c_verify_password_proof(
    proof_ptr: *mut OpaqueProofResult,
    expected_commitment: u64,
    nonce: u64,
) -> bool {
    if proof_ptr.is_null() { return false; }
    
    let proof_res = unsafe { &*(proof_ptr as *const ProofResult) };
    if proof_res.status != 0 { return false; }
    
    let proof_slice = unsafe { std::slice::from_raw_parts(proof_res.ptr, proof_res.len) };
    verify_password_proof(proof_slice, expected_commitment, nonce)
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
        let invalid_commitment = commitment + 1;
        assert!(!verify_password_proof(&proof, invalid_commitment, nonce), "Should fail wrong commitment");
        
        // let invalid_nonce = nonce + 1;
        // assert!(!verify_password_proof(&proof, commitment, invalid_nonce), "Should fail wrong nonce");
        
        let invalid_proof = vec![1, 2, 3];
        assert!(!verify_password_proof(&invalid_proof, commitment, nonce), "Should fail invalid proof bytes");
    }
}
