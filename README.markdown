# Threshold Paillier

A Rust implementation of the Threshold Paillier cryptosystem, providing secure multi-party computation with homomorphic encryption. This library is designed for applications requiring strong plaintext security, such as blockchain-based systems where ciphertexts are publicly exposed. It supports key generation, encryption, homomorphic operations (addition, scalar multiplication), partial decryption, and zero-knowledge proofs for verifying operations without revealing sensitive data.

## Features

- **Threshold Decryption**: Distributes private key shares among `l` parties, requiring `k` shares to decrypt.
- **Homomorphic Encryption**: Supports addition and scalar multiplication of ciphertexts.
- **Zero-Knowledge Proofs**: Includes proofs for encryption (`EncryptZK`), multiplication (`MulZK`), and partial decryption (`DecryptShareZK`) to ensure correctness without leaking secrets.
- **Constant-Time Operations**: Uses `crypto-bigint` for modular exponentiation to prevent timing attacks.
- **Secure Randomness**: Employs `OsRng` for cryptographic random number generation.
- **Safe Primes**: Generates safe primes using `rug` with 40 Miller-Rabin iterations for strong security.
- **Memory Safety**: Uses `zeroize` to clear sensitive data (e.g., secret shares) from memory.

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
threshold-paillier = "0.1.0"
```

The library depends on:
- `num-bigint` and `num-traits` for arbitrary-precision arithmetic.
- `rand` for secure random number generation.
- `thiserror` for error handling.
- `rug` for safe prime generation.
- `sha2` for SHA-256 hashing in zero-knowledge proofs.
- `crypto-bigint` for constant-time modular arithmetic.
- `zeroize` for secure memory handling.

## Usage

Below is an example of generating key shares, encrypting values, performing homomorphic addition, and decrypting with threshold shares:

```rust
use num_bigint::BigInt;
use threshold_paillier::ThresholdPaillier;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate key shares (bit_size=512, s=1, l=5, k=3)
    let result = ThresholdPaillier::new(512, 1, 5, 3)?;
    let pk = result.pub_key;
    let shares = result.key_shares;

    // Encrypt 12 and 25
    let twelve = BigInt::from(12);
    let twenty_five = BigInt::from(25);
    let (enc_twelve, zk) = pk.encrypt_with_proof(&twelve)?;
    zk.verify(&pk, &enc_twelve)?; // Verify encryption proof
    let (enc_twenty_five, _) = pk.encrypt(&twenty_five)?;

    // Homomorphic addition
    let sum = pk.add(&[enc_twelve, enc_twenty_five])?;

    // Partial decryption
    let mut decrypt_shares = Vec::new();
    for share in &shares {
        let (ds, zk) = share.partial_decrypt_with_proof(&sum)?;
        zk.verify(&pk, &sum, &ds)?; // Verify decryption proof
        decrypt_shares.push(ds);
    }

    // Combine shares to decrypt
    let decrypted = pk.combine_shares(&decrypt_shares)?;
    assert_eq!(decrypted, BigInt::from(37)); // 12 + 25 = 37
    Ok(())
}
```

## Security Considerations

- **Blockchain Exposure**: Ciphertexts and decryption shares may be public on a blockchain. The library uses `crypto-bigint` for constant-time modular exponentiation to prevent timing attacks.
- **Zero-Knowledge Proofs**: Non-interactive proofs (Fiat-Shamir with SHA-256) ensure operation correctness without revealing plaintexts or secret shares.
- **Primality Testing**: Uses 40 Miller-Rabin iterations for negligible false prime probability (~2^-80).
- **Sensitive Data**: Secret shares and private key components are zeroized using the `zeroize` crate.
- **Randomness**: All random numbers are generated using `OsRng`, equivalent to `/dev/urandom`.

**Warning**: This library has not been formally audited. Use in production systems requires thorough security review, especially for blockchain applications.

## Building and Testing

To build and test the library:

```bash
cargo build
cargo test
```

Benchmarks are provided using `criterion`:

```bash
cargo bench
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please submit issues or pull requests to the [repository](https://github.com/your-org/threshold-paillier). Ensure all code adheres to Rust’s safety and security standards.

## Acknowledgments

This library is a Rust port of the Go implementation by [niclabs/tcrsa](https://github.com/niclabs/tcrsa), adapted for enhanced security with constant-time operations and blockchain compatibility.