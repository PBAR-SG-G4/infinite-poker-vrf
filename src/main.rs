#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use schnorrkel::{Keypair, vrf::{VRFInOut, VRFPreOut, VRFProof}, context::signing_context};
use sha2::{Sha256, Digest};
use rand::Rng;

fn main() {
    // Player setup
    let keypair = Keypair::generate();
    let context = signing_context(b"example");

    // Commit phase
    let mut rng = rand::thread_rng();
    let seed: [u8; 32] = rng.gen();
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let _commitment = hasher.finalize();

    // Assume all players reveal their seeds and we combine them
    let revealed_seeds: Vec<[u8; 32]> = vec![seed];  // Simplified for one player
    let mut final_input = Vec::new();
    for seed in revealed_seeds {
        final_input.extend_from_slice(&seed);
    }
    let final_input_hash = Sha256::digest(&final_input);

    // Generate VRF output
    let vrf_output = keypair.vrf_sign(context.bytes(&final_input_hash));
    let (io, proof, _batchable) = vrf_output; // Include the third element in the destructuring

    // Convert VRFInOut to VRFPreOut for verification
    let vrf_preout_for_verification = io.to_preout();

    // Reveal and determine winner
    let verified = keypair.public.vrf_verify(context.bytes(&final_input_hash), &vrf_preout_for_verification,  &proof)
        .map_err(|e| format!("Invalid VRF proof: {:?}", e)).is_ok();

    if verified {
        // Convert to bytes
        let vrf_bytes = vrf_preout_for_verification.to_bytes();
        let card_value = vrf_bytes[0] % 52;
        println!("Card drawn: {}", card_value);
    } else {
        println!("VRF proof verification failed.");
    }
}
