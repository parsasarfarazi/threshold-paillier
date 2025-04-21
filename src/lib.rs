//! This crate implements the threshold Paillier cryptosystem.
//!
//! Based on:
//! [Damgård and Jurik, 2001](https://people.csail.mit.edu/rivest/voting/papers/DamgardJurikNielsen-AGeneralizationOfPailliersPublicKeySystemWithApplicationsToElectronicVoting.pdf)
//! This crate provides key generation, encryption, and threshold decryption using the Paillier scheme.
//!
//! # Example
//! ```
//! // TODO
//! ```

pub mod decryption_share;
pub mod functions;
pub mod polynomial;
pub mod pub_key;
pub mod tcpaillier;
pub mod threshold_share;
pub mod zk_proof;

pub use pub_key::PublicKey;
pub use tcpaillier::{FixedParams, NewKeyError, ThresholdPaillier};
pub use threshold_share::KeyShare;
pub use zk_proof::{DecryptShareZK, ZKProofError};
