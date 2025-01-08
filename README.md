# Secret Sharing and Verifiable Secret Sharing in Rust

This repository implements **Shamir's Secret Sharing (SSS)** and **Feldman's Verifiable Secret Sharing (VSS)** in Rust. These cryptographic schemes are used to securely split secrets into shares, distribute them to participants, and reconstruct the original secret from a subset of shares. The VSS implementation also ensures that shares are verifiable against commitments, preventing tampering.

## Features
- **Shamir's Secret Sharing**:
  - Split a secret into shares using polynomial interpolation.
  - Reconstruct the original secret from a minimum threshold of shares.
- **Feldman's Verifiable Secret Sharing**:
  - Create shares with cryptographic commitments.
  - Verify the integrity of shares.
  - Reconstruct the secret from valid shares.

---

## Getting Started

### Prerequisites
- **Rust**: Ensure you have Rust installed. If not, install it from [rust-lang.org](https://www.rust-lang.org/).

### Dependencies
This project uses the following crates:
- [`num-bigint`](https://crates.io/crates/num-bigint): For handling arbitrarily large integers.
- [`rand`](https://crates.io/crates/rand): For generating random numbers.

Install dependencies by running:
```bash
cargo build
```

### Running the Code
Execute the project with:
```bash
cargo run
```
This will demonstrate both SSS and VSS workflows.

---

## Code Overview

### Directory Structure
```
src/
├── main.rs       # Demonstrates SSS and VSS workflows
├── sss.rs        # Implements Shamir's Secret Sharing
├── vss.rs        # Implements Feldman's Verifiable Secret Sharing
```

### Key Components

#### `main.rs`
This file contains the entry point for the program and demonstrates the following workflows:
1. **Shamir's Secret Sharing**:
   - Splits a secret into shares.
   - Reconstructs the secret using the minimum required shares.
2. **Verifiable Secret Sharing**:
   - Splits a secret into verifiable shares with cryptographic commitments.
   - Verifies shares and reconstructs the secret.

#### `sss.rs`
Implements Shamir's Secret Sharing:
- **`SecretSharer` struct**:
  - `new`: Initializes with a prime modulus, threshold, and total shares.
  - `split_secret`: Splits a secret into shares using a random polynomial.
  - `reconstruct_secret`: Reconstructs the secret using Lagrange interpolation.

#### `vss.rs`
Implements Feldman's Verifiable Secret Sharing:
- **`FeldmanVSS` struct**:
  - `new`: Initializes with prime parameters, threshold, and total shares.
  - `split_secret`: Splits a secret into shares and generates commitments.
  - `verify_share`: Verifies a share against commitments.
  - `reconstruct_secret`: Reconstructs the secret using valid shares.

---

## Usage Examples

### Shamir's Secret Sharing
```rust
let secret = 22773311u64.to_biguint().unwrap();
let sharer = SecretSharer::new(3, 5);

let shares = sharer.split_secret(&secret);
assert_eq!(shares.len(), 5);

let reconstructed = sharer.reconstruct_secret(&shares[0..3]).unwrap();
assert_eq!(reconstructed, secret);
```

### Verifiable Secret Sharing
```rust
let p = BigUint::parse_bytes(b"115792089237316195423570985008687907853269984665640564039457584007908834671663", 10).unwrap();
let q = BigUint::parse_bytes(b"115792089237316195423570985008687907852837564279074904382605163141518161494337", 10).unwrap();
let g = BigUint::from(2u32);
let mut vss = FeldmanVSS::new(p, q, g, 3, 5);

let secret = 123456789u64.to_biguint().unwrap();
let (shares, commitments) = vss.split_secret(&secret).unwrap();

assert!(shares.iter().all(|share| vss.verify_share(share, &commitments)));
let reconstructed = vss.reconstruct_secret(&shares[0..3]).unwrap();
assert_eq!(reconstructed, secret);
```

---

## Best Practices
- **Prime Selection**: Use secure prime numbers for production environments (e.g., 256-bit or higher).
- **Threshold**: Ensure the threshold value matches the security and redundancy requirements of your application.
- **Testing**: Thoroughly test with various configurations of thresholds and share counts.

---

## Common Pitfalls
- **Insufficient Shares**: Ensure you provide at least the threshold number of shares for reconstruction.
- **Parameter Validation**: Check that `secret < q` and `threshold <= total_shares` in VSS to avoid runtime errors.
- **Randomness**: Use a cryptographically secure random number generator for production.

---

## Contributions
Contributions, issues, and feature requests are welcome! Feel free to fork this repository and submit pull requests.

---

## References
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [Feldman's Verifiable Secret Sharing](https://en.wikipedia.org/wiki/Verifiable_secret_sharing)
