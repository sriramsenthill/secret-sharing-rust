// File: src/main.rs
use crate::sss::SecretSharer;
use crate::vss::FeldmanVSS;
use num_bigint::ToBigUint;

mod sss;
mod vss;

fn main() {
    demo_shamir_secret_sharing();
    demo_verifiable_secret_sharing();
}

fn demo_shamir_secret_sharing() {
    println!("\n=== Demonstrating Shamir's Secret Sharing ===");

    // Create a secret
    let secret = 22773311u64.to_biguint().unwrap();
    println!("Original Secret: {}", secret);

    // Initialize SSS
    let sharer = SecretSharer::new(3, 5);

    // Generate shares
    let shares = sharer.split_secret(&secret);
    println!("\nGenerated {} shares:", shares.len());
    for (i, share) in shares.iter().enumerate() {
        println!("Share {}: x = {}, y = {}", i + 1, share.x, share.y);
    }

    // Reconstruct with minimum shares
    match sharer.reconstruct_secret(&shares[0..3]) {
        Some(reconstructed) => {
            println!("\nReconstructed secret: {}", reconstructed);
            assert_eq!(reconstructed, secret, "Reconstruction failed!");
        }
        None => println!("Failed to reconstruct secret"),
    }
}

fn demo_verifiable_secret_sharing() {
    println!("\n=== Demonstrating Verifiable Secret Sharing ===");

    // System parameters (using SECP256k1 parameters for real-world example)
    let p = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
        .parse::<num_bigint::BigUint>()
        .unwrap();
    let q = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
        .parse::<num_bigint::BigUint>()
        .unwrap();
    let g = 2u32.to_biguint().unwrap();

    // VSS parameters
    let threshold = 3;
    let total_shares = 5;

    // Initialize VSS
    let mut vss = FeldmanVSS::new(p, q, g, threshold, total_shares);

    // Create and share a secret
    let secret = 123456789u64.to_biguint().unwrap();
    println!("Original Secret: {}", secret);

    // Generate shares and commitments
    let (shares, commitments) = vss.split_secret(&secret).unwrap();

    // Display shares
    println!("\nGenerated shares:");
    for (i, share) in shares.iter().enumerate() {
        println!(
            "Share {}: ID = {}, Value = {}",
            i + 1,
            share.id,
            share.value
        );
    }

    // Verify shares
    println!("\nVerifying shares:");
    for (i, share) in shares.iter().enumerate() {
        let is_valid = vss.verify_share(share, &commitments);
        println!(
            "Share {} verification: {}",
            i + 1,
            if is_valid { "Valid" } else { "Invalid" }
        );
    }

    // Reconstruct secret
    let reconstructed = vss.reconstruct_secret(&shares[0..threshold]);
    match reconstructed {
        Some(value) => {
            println!("\nReconstructed secret: {}", value);
            assert_eq!(value, secret, "Reconstruction failed!");
        }
        None => println!("Failed to reconstruct secret"),
    }
}
