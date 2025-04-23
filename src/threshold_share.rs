use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use crate::decryption_share::DecryptionShare;
use crate::functions::random_int;
use crate::pub_key::{PubKeyError, PublicKey};

#[derive(Error, Debug)]
pub enum KeyShareError {
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    #[error("random number generation failed: {0}")]
    RandomNumberError(String),
    #[error("proof generation failed: {0}")]
    ProofGenerationError(String),
}

#[derive(Debug, Clone)]
pub struct KeyShare {
    pub pub_key: PublicKey,
    pub index: u8,
    pub si: BigInt,
}

impl Zeroize for KeyShare {
    fn zeroize(&mut self) {
        self.si = BigInt::zero();
        // Note: We don't zeroize pub_key or index as they're not considered sensitive
    }
}

impl Drop for KeyShare {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct DecryptShareZK {
    pub vi: BigInt,
    pub e: BigInt,
    pub v: BigInt,
    pub z: BigInt,
}

impl KeyShare {
    pub fn new(pub_key: PublicKey, index: u8, si: BigInt) -> Self {
        KeyShare { pub_key, index, si }
    }

    pub fn partial_decrypt(&self, c: &BigInt) -> Result<DecryptionShare, KeyShareError> {
        let n_to_s_plus_one = self.pub_key.get_n_to_s_plus_one();

        if c >= &n_to_s_plus_one || c < &BigInt::zero() {
            return Err(KeyShareError::InvalidCiphertext(
                "ciphertext out of bounds".to_string(),
            ));
        }

        // Calculate 2*delta*si mod n^(s+1)
        let delta_si_2 = (BigInt::from(2) * &self.pub_key.delta * &self.si) % &n_to_s_plus_one;
        
        // Compute c^(2*delta*si) mod n^(s+1)
        let pd = c.modpow(&delta_si_2, &n_to_s_plus_one);

        Ok(DecryptionShare {
            index: self.index,
            ci: pd,
        })
    }

    pub fn partial_decrypt_with_proof(
        &self,
        c: &BigInt,
    ) -> Result<(DecryptionShare, DecryptShareZK), KeyShareError> {
        let ds = self.partial_decrypt(c)?;
        let zk = self.partial_decrypt_proof(c, &ds)?;
        Ok((ds, zk))
    }

    pub fn partial_decrypt_proof(
        &self,
        c: &BigInt,
        ds: &DecryptionShare,
    ) -> Result<DecryptShareZK, KeyShareError> {
        let n_to_s_plus_one = self.pub_key.get_n_to_s_plus_one();

        let num_bits = (self.pub_key.s as usize + 2) * (self.pub_key.k as usize) + 256; // SHA256 size = 256 bits
        let r = random_int(num_bits).map_err(|e| KeyShareError::RandomNumberError(e.to_string()))?;

        // Use num_bigint operations
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);

        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let a = c_to_4.modpow(&r, &n_to_s_plus_one);
        let b = self.pub_key.v.modpow(&r, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);

        let mut hash = Sha256::new();
        let (_, a_bytes) = a.to_bytes_le();
        hash.update(&a_bytes);
        let (_, b_bytes) = b.to_bytes_le();
        hash.update(&b_bytes);
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        let e_si_delta = (&self.si * &e * &self.pub_key.delta) % &n_to_s_plus_one;
        let z = (&e_si_delta + &r) % &n_to_s_plus_one;

        let vi = self
            .pub_key
            .vi
            .get(self.index as usize - 1)
            .cloned()
            .ok_or_else(|| KeyShareError::ProofGenerationError("invalid index".to_string()))?;

        Ok(DecryptShareZK {
            vi,
            e,
            v: self.pub_key.v.clone(),
            z,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::{factorial, generate_safe_primes};
    use crate::zk_proof::DecryptShareZK as ZKProof;
    use num_traits::{One, Pow};
    use num_integer::Integer;

    // Test helper to create a test PublicKey and related data
    fn create_test_key_and_share(index: u8) -> (PublicKey, KeyShare, BigInt) {
        // Generate small primes for testing (smaller bit size for faster tests)
        let bit_size = 512;
        let (p, q) = generate_safe_primes(bit_size).unwrap();
        let n = &p * &q;
        let s: u8 = 1;
        let k: u8 = 3;
        let l: u8 = 5;
        
        // Create a random v
        let r = random_int(bit_size * 4).unwrap();
        let n_to_s_plus_one = n.clone().pow((s as u32) + 1);
        let v = r.modpow(&BigInt::from(2), &n_to_s_plus_one);
        
        let delta = factorial(l as u64);
        let n_to_s = n.clone().pow(s as u32);
        let constant = mod_inverse(&(BigInt::from(4) * &delta * &delta), &n_to_s).unwrap();
        
        // Create PublicKey
        let mut pk = PublicKey::new_uncached(
            n.clone(),
            v.clone(),
            l,
            k,
            s,
            delta.clone(),
            constant,
        );
        
        // Initialize vi values for the test
        for i in 0..l as usize {
            pk.vi[i] = BigInt::from((i as u64 + 1) * 1000);
        }
        
        // Create a private key share (normally this would be generated via a secure protocol)
        // For testing, we just create a random value
        let si = random_int(bit_size).unwrap();
        
        let key_share = KeyShare::new(pk.clone(), index, si.clone());
        
        (pk, key_share, n)
    }

    // Helper function for mod inverse calculation
    fn mod_inverse(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
        let gcd = a.gcd(modulus);
        if gcd != BigInt::one() {
            return None;
        }
        
        let result = a.extended_gcd(modulus);
        let mut t = result.x;
        if t < BigInt::zero() {
            t += modulus;
        }
        Some(t)
    }
    
    fn encrypt_test_message(pk: &PublicKey, message: i64) -> BigInt {
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_plus_one = pk.get_n_plus_one();
        let msg = BigInt::from(message);
        
        // Get a random r in Z*_{n^(s+1)}
        let r = random_int(512 * 4).unwrap();
        
        // Create ciphertext c = (1+n)^m * r^n mod n^(s+1)
        let ciphertext = (n_plus_one.modpow(&msg, &n_to_s_plus_one) * 
                       r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
                       
        ciphertext
    }

    #[test]
    fn test_key_share_new() {
        let (pk, _, n) = create_test_key_and_share(1);
        let si = BigInt::from(123456);
        let index: u8 = 2;
        
        let key_share = KeyShare::new(pk.clone(), index, si.clone());
        
        assert_eq!(key_share.index, index);
        assert_eq!(key_share.si, si);
        assert_eq!(key_share.pub_key.n, n);
    }
    
    #[test]
    fn test_key_share_zeroize() {
        let (pk, _, _) = create_test_key_and_share(1);
        let si = BigInt::from(123456);
        let index: u8 = 2;
        
        let mut key_share = KeyShare::new(pk, index, si.clone());
        
        // Verify initial state
        assert_eq!(key_share.si, si);
        
        // Zeroize and check
        key_share.zeroize();
        assert_eq!(key_share.si, BigInt::zero());
        
        // Other fields should not be affected
        assert_eq!(key_share.index, index);
    }
    
    #[test]
    fn test_partial_decrypt_valid_ciphertext() {
        let (pk, key_share, _) = create_test_key_and_share(1);
        
        // Encrypt a test message
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        // Perform partial decryption
        let result = key_share.partial_decrypt(&ciphertext);
        assert!(result.is_ok(), "Partial decryption should succeed with valid ciphertext");
        
        let decryption_share = result.unwrap();
        assert_eq!(decryption_share.index, key_share.index);
        assert!(!decryption_share.ci.is_zero(), "Partial decryption should produce non-zero result");
    }
    
    #[test]
    fn test_partial_decrypt_invalid_ciphertext_too_large() {
        let (_, key_share, _) = create_test_key_and_share(1);
        
        // Create an invalid ciphertext that's too large
        let invalid_ciphertext = key_share.pub_key.get_n_to_s_plus_one() + BigInt::one();
        
        // Attempt partial decryption with invalid ciphertext
        let result = key_share.partial_decrypt(&invalid_ciphertext);
        
        assert!(result.is_err());
        match result {
            Err(KeyShareError::InvalidCiphertext(_)) => {
                // This is the expected error
            }
            _ => panic!("Expected InvalidCiphertext error"),
        }
    }
    
    #[test]
    fn test_partial_decrypt_invalid_ciphertext_negative() {
        let (_, key_share, _) = create_test_key_and_share(1);
        
        // Create an invalid negative ciphertext
        let invalid_ciphertext = BigInt::from(-1);
        
        // Attempt partial decryption with invalid ciphertext
        let result = key_share.partial_decrypt(&invalid_ciphertext);
        
        assert!(result.is_err());
        match result {
            Err(KeyShareError::InvalidCiphertext(_)) => {
                // This is the expected error
            }
            _ => panic!("Expected InvalidCiphertext error"),
        }
    }
    
    #[test]
    fn test_partial_decrypt_with_proof() {
        let (pk, key_share, _) = create_test_key_and_share(1);
        
        // Encrypt a test message
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        // Perform partial decryption with proof
        let result = key_share.partial_decrypt_with_proof(&ciphertext);
        assert!(result.is_ok(), "Partial decryption with proof should succeed with valid ciphertext");
        
        let (decryption_share, proof) = result.unwrap();
        assert_eq!(decryption_share.index, key_share.index);
        assert!(!decryption_share.ci.is_zero());
        
        // Verify the proof contains expected values
        assert_eq!(proof.v, pk.v);
        assert_eq!(proof.vi, pk.vi[key_share.index as usize - 1]);
        assert!(!proof.e.is_zero());
        assert!(!proof.z.is_zero());
    }
    
    #[test]
    fn test_partial_decrypt_proof_validations() {
        let (pk, key_share, _) = create_test_key_and_share(1);
        
        // Encrypt a test message
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        // First get a valid decryption share
        let decryption_share = key_share.partial_decrypt(&ciphertext).unwrap();
        
        // Generate proof separately
        let proof_result = key_share.partial_decrypt_proof(&ciphertext, &decryption_share);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        
        // Verify proof has correct structure
        assert_eq!(proof.v, pk.v);
        assert_eq!(proof.vi, pk.vi[key_share.index as usize - 1]);
        
        // The e and z values should be non-zero
        assert!(!proof.e.is_zero());
        assert!(!proof.z.is_zero());
        
        // Verify this proof using the ZKProof module
        let zk_proof = ZKProof {
            v: proof.v,
            vi: proof.vi,
            z: proof.z,
            e: proof.e,
        };
        
        let verification_result = zk_proof.verify(&pk, &ciphertext, &decryption_share);
        assert!(verification_result.is_ok(), "ZK proof verification should succeed");
    }
    
    #[test]
    fn test_partial_decrypt_proof_with_invalid_index() {
        let (pk, mut key_share, _) = create_test_key_and_share(1);
        
        // Encrypt a test message
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        // Get a valid decryption share
        let decryption_share = key_share.partial_decrypt(&ciphertext).unwrap();
        
        // Change key_share index to an invalid value (out of bounds)
        key_share.index = pk.l + 1; // This is outside the valid range
        
        // Try to generate proof with invalid index
        let proof_result = key_share.partial_decrypt_proof(&ciphertext, &decryption_share);
        
        assert!(proof_result.is_err());
        match proof_result {
            Err(KeyShareError::ProofGenerationError(_)) => {
                // This is the expected error
            }
            _ => panic!("Expected ProofGenerationError error"),
        }
    }
    
    #[test]
    fn test_multiple_decrypt_shares() {
        // Create a threshold setup with multiple shares
        let (pk, _, _) = create_test_key_and_share(1);
        
        // Create multiple key shares
        let shares_count = pk.k;
        let mut key_shares = Vec::new();
        
        for i in 1..=shares_count {
            let (_, key_share, _) = create_test_key_and_share(i);
            key_shares.push(key_share);
        }
        
        // Encrypt a test message
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        // Generate partial decryptions from each share
        let mut decrypt_shares = Vec::new();
        for key_share in &key_shares {
            let decrypt_share = key_share.partial_decrypt(&ciphertext).unwrap();
            decrypt_shares.push(decrypt_share);
        }
        
        // Verify we have the expected number of shares
        assert_eq!(decrypt_shares.len(), shares_count as usize);
        
        // Verify each share has the correct index
        for i in 0..shares_count as usize {
            assert_eq!(decrypt_shares[i].index, (i + 1) as u8);
        }
    }
    
    #[test]
    fn test_key_share_drop_zeroizes() {
        let (pk, _, _) = create_test_key_and_share(1);
        let si = BigInt::from(123456);
        let index: u8 = 2;
        
        // Create a key share and verify its initial state
        let key_share = KeyShare::new(pk, index, si.clone());
        assert_eq!(key_share.si, si);
        
        // We can't directly test Drop, but we can verify that Zeroize works
        // which is called by Drop
        let mut key_share2 = key_share.clone();
        key_share2.zeroize();
        assert_eq!(key_share2.si, BigInt::zero());
    }
    
    #[test]
    fn test_partial_decrypt_with_debug_display() {
        let (pk, key_share, _) = create_test_key_and_share(1);
        
        // Test that Debug trait is implemented
        let debug_output = format!("{:?}", key_share);
        assert!(debug_output.contains("KeyShare"));
        
        // Generate a partial decryption
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        let result = key_share.partial_decrypt_with_proof(&ciphertext).unwrap();
        
        // Test that Debug is implemented for DecryptShareZK
        let debug_output = format!("{:?}", result.1);
        assert!(debug_output.contains("DecryptShareZK"));
    }
    
    #[test]
    fn test_clone_correctness() {
        let (pk, key_share, _) = create_test_key_and_share(1);
        
        // Clone the key share
        let cloned_share = key_share.clone();
        
        // Verify that the clone has the same values
        assert_eq!(cloned_share.index, key_share.index);
        assert_eq!(cloned_share.si, key_share.si);
        
        // Both should produce the same partial decryption
        let message = 42;
        let ciphertext = encrypt_test_message(&pk, message);
        
        let decrypt1 = key_share.partial_decrypt(&ciphertext).unwrap();
        let decrypt2 = cloned_share.partial_decrypt(&ciphertext).unwrap();
        
        assert_eq!(decrypt1.index, decrypt2.index);
        assert_eq!(decrypt1.ci, decrypt2.ci);
    }
}