//! This crate implements the threshold Paillier cryptosystem.
//!
//! Based on:
//! [Damgård and Jurik, 2001](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf)
//! This crate provides key generation, encryption, and threshold decryption using the Paillier scheme.
//!
//! # Example
//! ```
//! use threshold_paillier::keygen;
//! let (pk, shares) = keygen(2, 3);
//! ```


fn main() {
    println!("Hello, world!");
}
