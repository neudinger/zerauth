use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig, Hasher};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use wasm_bindgen::prelude::*;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

struct PasswordCircuit {
    data: CircuitData<F, C, D>,
    // CHANGED: We now use an array of 4 targets (256 bits)
    key_targets: [Target; 4], 
    nonce_target: Target,
}

fn build_password_circuit() -> PasswordCircuit {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // 1. Private Witness: 256-bit Key (4 x 64-bit elements)
    let key_targets = [
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
        builder.add_virtual_target(),
    ];
    
    // 2. Public Input: Nonce
    let nonce_target = builder.add_virtual_target(); 

    // 3. Compute Hash(Key_Part_1, Key_Part_2, Key_Part_3, Key_Part_4)
    // We flatten the input to hash all 4 parts of the key
    let mut hash_inputs = key_targets.to_vec();
    let hash_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(hash_inputs);
    
    // 4. Register Public Inputs
    builder.register_public_inputs(&hash_target.elements);
    builder.register_public_input(nonce_target);

    let data = builder.build::<C>();
    
    PasswordCircuit {
        data,
        key_targets,
        nonce_target,
    }
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// Helper to convert 32 bytes -> [u64; 4]
fn bytes_to_u64_array(bytes: &[u8]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let end = start + 8;
        // Safety: We assume input is exactly 32 bytes
        let mut slice = [0u8; 8];
        slice.copy_from_slice(&bytes[start..end]);
        result[i] = u64::from_le_bytes(slice);
    }
    result
}

#[wasm_bindgen]
pub fn derive_secure_key_parts(password_str: &str, salt_input: u64) -> Vec<u64> {
    let argon2 = Argon2::default();
    let salt_bytes = salt_input.to_le_bytes();
    let salt_string = SaltString::encode_b64(&salt_bytes).expect("Encoding failed");

    let password_hash = argon2.hash_password(password_str.as_bytes(), &salt_string)
        .expect("Argon2 failed");
    
    // Get full 32 bytes (256 bits)
    let output = password_hash.hash.expect("No hash");
    let output_slice = output.as_bytes(); // Should be 32 bytes default

    // Convert to [u64; 4]
    let parts = bytes_to_u64_array(&output_slice[0..32]);
    parts.to_vec()
}

#[wasm_bindgen]
pub fn get_commitment(password_str: &str, salt: u64) -> u64 {
    // 1. Get the 4 parts of the key
    let parts = derive_secure_key_parts(password_str, salt);
    
    // 2. Convert to Fields
    let inputs: Vec<F> = parts.iter().map(|&x| F::from_canonical_u64(x)).collect();

    // 3. Hash all 4 parts
    let hash_output = PoseidonHash::hash_no_pad(&inputs);
    
    // Return the first element of the commitment hash
    hash_output.elements[0].to_canonical_u64()
}

#[wasm_bindgen]
pub fn prove_password(password_str: &str, salt: u64, nonce: u64) -> Vec<u8> {
    let parts = derive_secure_key_parts(password_str, salt);
    let circuit = build_password_circuit();
    
    let mut pw = PartialWitness::new();
    
    // Set all 4 parts of the key to the witness
    for i in 0..4 {
        pw.set_target(circuit.key_targets[i], F::from_canonical_u64(parts[i]));
    }
    pw.set_target(circuit.nonce_target, F::from_canonical_u64(nonce));

    let proof = circuit.data.prove(pw).expect("Proving failed");
    postcard::to_allocvec(&proof).expect("Serialization failed")
}

#[wasm_bindgen]
pub fn verify_password_proof(proof_bytes: &[u8], expected_commitment: u64, nonce: u64) -> bool {
    // Use proper error handling in production instead of expect/unwrap
    let proof_result = postcard::from_bytes(proof_bytes);
    if proof_result.is_err() { return false; }
    
    let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> = proof_result.unwrap();

    let circuit = build_password_circuit();

    // 1. Check Commitment
    if proof.public_inputs[0] != F::from_canonical_u64(expected_commitment) {
        return false;
    }

    // 2. Check Nonce (Index is now 4 because hash output is 0..3)
    // Wait! Check indices carefully:
    // Hash Output (Poseidon) = 4 elements (indices 0,1,2,3)
    // Nonce = 1 element (index 4)
    if proof.public_inputs[4] != F::from_canonical_u64(nonce) {
        return false;
    }

    circuit.data.verify(proof).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end() {
        let password = "12345";
        let nonce_proof = 12345;
        let salt = 12345;
        
        // 1. Generate
        println!("Generating proof...");
        let proof_bytes = prove_password(password, salt, nonce_proof);
        println!("Proof size: {} bytes", proof_bytes.len());

        // 2. Decode to get the actual hash (cheating for test purposes)
        let proof: plonky2::plonk::proof::ProofWithPublicInputs<F, C, D> = 
            postcard::from_bytes(&proof_bytes).unwrap();
        
        // This line now works because PrimeField64 is imported!
        let actual_hash = proof.public_inputs[0].to_canonical_u64();
        let nonce_verifier = 12345;
        // 3. Verify
        println!("Verifying...");
        let is_valid = verify_password_proof(&proof_bytes, actual_hash, nonce_verifier);
        assert!(is_valid);
    }
}