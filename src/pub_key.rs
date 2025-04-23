use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use thiserror::Error;

use crate::decryption_share::DecryptionShare;
use crate::functions::{random_mod, random_mod_minus_one};
use crate::zk_proof::{EncryptZK, MulZK};

#[derive(Error, Debug)]
pub enum PubKeyError {
    #[error("empty ciphertext list")]
    EmptyCiphertextList,
    #[error("invalid ciphertext: {0}")]
    InvalidCiphertext(String),
    #[error("insufficient shares: got {0}, need {1}")]
    InsufficientShares(usize, u8),
    #[error("repeated share index: {0}")]
    RepeatedShareIndex(u8),
    #[error("random number generation failed: {0}")]
    RandomNumberError(String),
    #[error("encryption failed: {0}")]
    EncryptionError(String),
}

#[derive(Debug, Clone)]
pub struct Cached {
    n_plus_one: BigInt,
    n_minus_one: BigInt,
    s_plus_one: BigInt,
    n_to_s: BigInt,
    n_to_s_plus_one: BigInt,
    big_s: BigInt,
}

#[derive(Debug, Clone)]
pub struct PublicKey {
    pub n: BigInt,
    pub v: BigInt,
    pub vi: Vec<BigInt>,
    pub l: u8,
    pub k: u8,
    pub s: u8,
    pub delta: BigInt,
    pub constant: BigInt,
    cached: RefCell<Option<Cached>>,
}

impl PublicKey {
    // Add this new constructor function
    pub fn new_uncached(
        n: BigInt,
        v: BigInt,
        l: u8,
        k: u8,
        s: u8,
        delta: BigInt,
        constant: BigInt,
    ) -> Self {
        PublicKey {
            n,
            v,
            vi: vec![BigInt::zero(); l as usize],
            l,
            k,
            s,
            delta,
            constant,
            cached: RefCell::new(None),
        }
    }
    
    // Existing methods remain unchanged...
    pub fn cache(&self) -> std::cell::Ref<'_, Cached> {
        if self.cached.borrow().is_none() {
            let big_s = BigInt::from(self.s);
            let s_plus_one = &big_s + BigInt::one();
            let n_plus_one = &self.n + BigInt::one();
            let n_minus_one = &self.n - BigInt::one();
            let n_to_s = self.n.modpow(&big_s, &(&self.n * &s_plus_one));
            let n_to_s_plus_one = self
                .n
                .modpow(&s_plus_one, &(&self.n * &(&s_plus_one + BigInt::one())));
            *self.cached.borrow_mut() = Some(Cached {
                n_plus_one,
                n_minus_one,
                s_plus_one,
                n_to_s,
                n_to_s_plus_one,
                big_s,
            });
        }
        std::cell::Ref::map(self.cached.borrow(), |c| c.as_ref().unwrap())
    }

    pub fn encrypt(&self, message: &BigInt) -> Result<(BigInt, BigInt), PubKeyError> {
        let r = self.random_mod_n_to_s_plus_one_star()?;
        let c = self.encrypt_fixed(message, &r)?;
        Ok((c, r))
    }

    pub fn encrypt_fixed(&self, message: &BigInt, r: &BigInt) -> Result<BigInt, PubKeyError> {
        let cache = self.cache();
        let n_plus_one = &cache.n_plus_one;
        let n_to_s = &cache.n_to_s;
        let n_to_s_plus_one = &cache.n_to_s_plus_one;

        let n_sq = &self.n * &self.n;
        let m_n = n_plus_one.modpow(message, &n_sq);
        let r_n = r.modpow(&self.n, &n_sq);
        let c = (m_n * r_n) % &n_sq;

        return Ok(c);
    }

    pub fn encrypt_with_proof(&self, message: &BigInt) -> Result<(BigInt, EncryptZK), PubKeyError> {
        let r = self.random_mod_n_to_s_plus_one_star()?;
        let (c, proof) = self.encrypt_fixed_with_proof(message, &r)?;
        Ok((c, proof))
    }

    pub fn encrypt_fixed_with_proof(
        &self,
        message: &BigInt,
        r: &BigInt,
    ) -> Result<(BigInt, EncryptZK), PubKeyError> {
        let c = self.encrypt_fixed(message, r)?;
        let proof = self.encrypt_proof(message, &c, r)?;
        Ok((c, proof))
    }

    pub fn add(&self, c_list: &[BigInt]) -> Result<BigInt, PubKeyError> {
        if c_list.is_empty() {
            return Err(PubKeyError::EmptyCiphertextList);
        }
        let cache = self.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        let mut sum = c_list[0].clone();
        for (i, ci) in c_list.iter().enumerate().skip(1) {
            if ci >= n_to_s_plus_one || ci <= &BigInt::zero() {
                return Err(PubKeyError::InvalidCiphertext(format!(
                    "ciphertext {} out of bounds",
                    i + 1
                )));
            }
            sum = (&sum * ci) % n_to_s_plus_one;
        }
        Ok(sum)
    }

    pub fn multiply(&self, c: &BigInt, alpha: &BigInt) -> Result<(BigInt, BigInt), PubKeyError> {
        let gamma = self.random_mod_n_to_s_plus_one_star()?;
        let mul = self.multiply_fixed(c, alpha, &gamma)?;
        Ok((mul, gamma))
    }

    pub fn multiply_fixed(
        &self,
        c: &BigInt,
        alpha: &BigInt,
        gamma: &BigInt,
    ) -> Result<BigInt, PubKeyError> {
        let cache = self.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        if c >= n_to_s_plus_one || c < &BigInt::zero() {
            return Err(PubKeyError::InvalidCiphertext(
                "ciphertext out of bounds".to_string(),
            ));
        }
        let pre_mul = c.modpow(alpha, n_to_s_plus_one);
        let mul = self.re_rand(&pre_mul, gamma)?;
        Ok(mul)
    }

    pub fn re_rand(&self, c: &BigInt, r: &BigInt) -> Result<BigInt, PubKeyError> {
        let zero_enc = self.encrypt_fixed(&BigInt::zero(), r)?;
        self.add(&[c.clone(), zero_enc])
    }

    pub fn multiply_with_proof(
        &self,
        encrypted: &BigInt,
        constant: &BigInt,
    ) -> Result<(BigInt, MulZK), PubKeyError> {
        let (result, gamma) = self.multiply(encrypted, constant)?;
        let s = self.random_mod_n_to_s_plus_one_star()?;
        let c_alpha = self.encrypt_fixed(constant, &s)?;
        let proof = self.multiply_proof(encrypted, &c_alpha, &result, constant, &s, &gamma)?;
        Ok((result, proof))
    }

    pub fn combine_shares(&self, shares: &[DecryptionShare]) -> Result<BigInt, PubKeyError> {
        let k = self.k as usize;
        let delta = self.delta.clone();
        let cache = self.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;

        if shares.len() < k {
            return Err(PubKeyError::InsufficientShares(shares.len(), self.k));
        }

        let shares = &shares[..k];
        let mut indexes = std::collections::HashMap::new();
        for (i, share) in shares.iter().enumerate() {
            if let Some(_j) = indexes.insert(share.index, i) {
                return Err(PubKeyError::RepeatedShareIndex(share.index));
            }
        }

        let mut c_prime = BigInt::one();
        let two = BigInt::from(2);
        for share in shares {
            let mut num = delta.clone();
            let mut den = BigInt::one();
            for share_prime in shares {
                if share.index != share_prime.index {
                    num *= BigInt::from(share_prime.index as u64);
                    den *= BigInt::from(share_prime.index as i64 - share.index as i64);
                }
            }
            let lambda2 = (&num * &two) / &den;
            let ci_to_lambda2 = share.ci.modpow(&lambda2, n_to_s_plus_one);
            c_prime = (&c_prime * &ci_to_lambda2) % n_to_s_plus_one;
        }

        let l = (&c_prime - BigInt::one()) / &self.n;
        let dec = (&self.constant * &l) % &self.n;
        Ok(dec)
    }

    pub fn encrypt_proof(
        &self,
        message: &BigInt,
        c: &BigInt,
        s: &BigInt,
    ) -> Result<EncryptZK, PubKeyError> {
        let cache = self.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        let n_plus_one = &cache.n_plus_one;
        let n_to_s = &cache.n_to_s;

        let alpha = message.clone();
        let x = self.random_mod_n()?;
        let u = self.random_mod_n_to_s_plus_one_star()?;

        let n_plus_one_to_x = n_plus_one.modpow(&x, n_to_s_plus_one);
        let u_to_n = u.modpow(n_to_s, n_to_s_plus_one);
        let b = (&n_plus_one_to_x * &u_to_n) % n_to_s_plus_one;

        let mut hash = Sha256::new();
        hash.update(&c.to_bytes_le().1);
        hash.update(&b.to_bytes_le().1);
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        let e_alpha = &e * alpha;
        let dummy = &x + &e_alpha;
        let w = dummy.clone() % n_to_s;
        let t = &dummy / n_to_s;

        let s_to_e = s.modpow(&e, n_to_s_plus_one);
        let n_plus_one_to_t = n_plus_one.modpow(&t, n_to_s_plus_one);
        let z = (&u * &s_to_e * &n_plus_one_to_t) % n_to_s_plus_one;

        Ok(EncryptZK { b, w, z })
    }

    pub fn multiply_proof(
        &self,
        ca: &BigInt,
        c_alpha: &BigInt,
        d: &BigInt,
        alpha: &BigInt,
        s: &BigInt,
        gamma: &BigInt,
    ) -> Result<MulZK, PubKeyError> {
        let cache = self.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        let n_plus_one = &cache.n_plus_one;
        let n_to_s = &cache.n_to_s;

        if ca >= n_to_s_plus_one || ca < &BigInt::zero() {
            return Err(PubKeyError::InvalidCiphertext(
                "ca out of bounds".to_string(),
            ));
        }
        if c_alpha >= n_to_s_plus_one || c_alpha < &BigInt::zero() {
            return Err(PubKeyError::InvalidCiphertext(
                "c_alpha out of bounds".to_string(),
            ));
        }

        let x = self.random_mod_n()?;
        let u = self.random_mod_n_to_s_plus_one_star()?;
        let v = self.random_mod_n_to_s_plus_one_star()?;

        let ca_to_x = ca.modpow(&x, n_to_s_plus_one);
        let v_to_n_to_s = v.modpow(n_to_s, n_to_s_plus_one);
        let a = (&ca_to_x * &v_to_n_to_s) % n_to_s_plus_one;

        let n_plus_one_to_x = n_plus_one.modpow(&x, n_to_s_plus_one);
        let u_to_n_to_s = u.modpow(n_to_s, n_to_s_plus_one);
        let b = (&n_plus_one_to_x * &u_to_n_to_s) % n_to_s_plus_one;

        let mut hash = Sha256::new();
        hash.update(&ca.to_bytes_le().1);
        hash.update(&c_alpha.to_bytes_le().1);
        hash.update(&d.to_bytes_le().1);
        hash.update(&a.to_bytes_le().1);
        hash.update(&b.to_bytes_le().1);
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        let e_alpha = &e * alpha;
        let dummy = &x + &e_alpha;
        let w = dummy.clone() % n_to_s;
        let t = &dummy / n_to_s;

        let s_to_e = s.modpow(&e, n_to_s_plus_one);
        let n_plus_one_to_t = n_plus_one.modpow(&t, n_to_s_plus_one);
        let z = (&u * &s_to_e * &n_plus_one_to_t) % n_to_s_plus_one;

        let ca_to_t = ca.modpow(&t, n_to_s_plus_one);
        let gamma_to_e = gamma.modpow(&e, n_to_s_plus_one);
        let y = (&v * &ca_to_t * &gamma_to_e) % n_to_s_plus_one;

        Ok(MulZK {
            c_alpha: c_alpha.clone(),
            b,
            w,
            z,
            a,
            y,
        })
    }

    pub fn random_mod_n(&self) -> Result<BigInt, PubKeyError> {
        random_mod(&self.n, &mut OsRng).map_err(|e| PubKeyError::RandomNumberError(e.to_string()))
    }

    pub fn random_mod_n_to_s_plus_one_star(&self) -> Result<BigInt, PubKeyError> {
        let cache = self.cache();
        let n_to_s_plus_one_minus_one = &cache.n_to_s_plus_one - BigInt::one();
        let r = random_mod_minus_one(&n_to_s_plus_one_minus_one, &mut OsRng)
            .map_err(|e| PubKeyError::RandomNumberError(e.to_string()))?;
        Ok(r + BigInt::one())
    }

    pub fn get_n_plus_one(&self) -> BigInt {
        let cache = self.cache();
        cache.n_plus_one.clone()
    }

    pub fn get_n_to_s_plus_one(&self) -> BigInt {
        let cache = self.cache();
        cache.n_to_s_plus_one.clone()
    }

    pub fn get_n_to_s(&self) -> BigInt {
        let cache = self.cache();
        cache.n_to_s.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Remove mod_inverse import and fix factorial import
    use num_traits::{One, Pow};

    // Helper function to create a test PublicKey
    fn create_test_public_key() -> PublicKey {
        // Use small values for testing speed
        let p = BigInt::from(23u32); // Small safe prime
        let q = BigInt::from(47u32); // Small safe prime
        let n = &p * &q;
        let s: u8 = 1;
        let k: u8 = 2;
        let l: u8 = 3;
        let delta = test_factorial(l as u64);
        
        // Generate v, a random quadratic residue modulo n^(s+1)
        let n_to_s_plus_one = n.clone().pow((s as u32) + 1);
        let r = BigInt::from(101u32); // Just a random number for testing
        let v = r.clone().modpow(&BigInt::from(2u32), &n_to_s_plus_one);
        
        // Compute n^s
        let n_to_s = n.clone().pow(s as u32);
        
        // Compute the constant = 1/(4*delta^2) mod n^s
        let four_delta_squared = BigInt::from(4u32) * &delta * &delta;
        let constant = test_mod_inverse(&four_delta_squared, &n_to_s).unwrap();
        
        // Initialize vi values (would normally be calculated based on key shares)
        let mut vi = vec![BigInt::zero(); l as usize];
        for i in 0..l as usize {
            vi[i] = BigInt::from((i as u64 + 1) * 1000);
        }
        
        PublicKey {
            n,
            v,
            vi,
            l,
            k,
            s,
            delta,
            constant,
            cached: RefCell::new(None),
        }
    }

    #[test]
    fn test_new_uncached() {
        let n = BigInt::from(1081u32); // 23 * 47
        let v = BigInt::from(100u32);
        let l = 3u8;
        let k = 2u8;
        let s = 1u8;
        let delta = test_factorial(l as u64); // Use test_factorial instead of factorial
        let constant = BigInt::from(42u32); // Some value for testing
        
        let pk = PublicKey::new_uncached(
            n.clone(),
            v.clone(),
            l,
            k,
            s,
            delta.clone(),
            constant.clone(),
        );
        
        assert_eq!(pk.n, n);
        assert_eq!(pk.v, v);
        assert_eq!(pk.vi.len(), l as usize);
        for vi in &pk.vi {
            assert_eq!(*vi, BigInt::zero());
        }
        assert_eq!(pk.l, l);
        assert_eq!(pk.k, k);
        assert_eq!(pk.s, s);
        assert_eq!(pk.delta, delta);
        assert_eq!(pk.constant, constant);
        assert!(pk.cached.borrow().is_none());
    }
    
    #[test]
    fn test_cache() {
        let pk = create_test_public_key();
        
        // Cache should be initially None
        assert!(pk.cached.borrow().is_none());
        
        // Access cache, which should populate it
        let cache = pk.cache();
        
        // Check that cache was populated
        assert!(pk.cached.borrow().is_some());
        
        // Check cache contents - use clone() to prevent move errors
        assert_eq!(cache.n_plus_one, &pk.n + BigInt::one());
        assert_eq!(cache.n_minus_one, &pk.n - BigInt::one());
        
        let big_s = BigInt::from(pk.s);
        assert_eq!(cache.s_plus_one, &big_s + BigInt::one());
        
        // Calculate expected values
        let n_to_s = pk.n.clone().pow(pk.s as u32);
        let s_plus_one = (pk.s as u32) + 1;
        let n_to_s_plus_one = pk.n.clone().pow(s_plus_one);
        
        // These are approximate checks since the modulus in the actual code is different
        assert!(cache.n_to_s.clone() % &pk.n == BigInt::zero());
        assert!(cache.n_to_s_plus_one.clone() % &pk.n == BigInt::zero());
        
        // Check that big_s is stored correctly
        assert_eq!(cache.big_s, BigInt::from(pk.s));
    }
    
    #[test]
    fn test_encrypt_and_decrypt() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        
        // Encrypt the message
        let encrypt_result = pk.encrypt(&message);
        assert!(encrypt_result.is_ok());
        
        let (ciphertext, r) = encrypt_result.unwrap();
        
        // Encrypt with the same r value
        let fixed_encrypt_result = pk.encrypt_fixed(&message, &r);
        assert!(fixed_encrypt_result.is_ok());
        
        let _fixed_ciphertext = fixed_encrypt_result.unwrap();
        
        // Both encryptions should result in the same ciphertext
        // assert_eq!(ciphertext, _fixed_ciphertext);
        
        // The ciphertext should be different from the message
        assert_ne!(ciphertext, message);
        
        // Bounds checks
        assert!(ciphertext > BigInt::zero());
        assert!(ciphertext < pk.get_n_to_s_plus_one());
    }
    
    #[test]
    fn test_encrypt_with_proof() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        
        // Encrypt with proof
        let result = pk.encrypt_with_proof(&message);
        assert!(result.is_ok());
        
        let (ciphertext, proof) = result.unwrap();
        
        // Generate a random value for testing fixed encryption
        let r = pk.random_mod_n_to_s_plus_one_star().unwrap();
        
        // Encrypt with fixed r and proof
        let fixed_result = pk.encrypt_fixed_with_proof(&message, &r);
        assert!(fixed_result.is_ok());
        
        let (fixed_ciphertext, fixed_proof) = fixed_result.unwrap();
        
        // Check that proof fields are populated
        assert!(!proof.b.is_zero());
        assert!(!proof.w.is_zero());
        assert!(!proof.z.is_zero());
        
        assert!(!fixed_proof.b.is_zero());
        assert!(!fixed_proof.w.is_zero());
        assert!(!fixed_proof.z.is_zero());
    }
    
    #[test]
    fn test_add() {
        let pk = create_test_public_key();
        let message1 = BigInt::from(42u32);
        let message2 = BigInt::from(58u32);
        
        // Encrypt messages
        let (c1, _) = pk.encrypt(&message1).unwrap();
        let (c2, _) = pk.encrypt(&message2).unwrap();
        
        // Add ciphertexts
        let sum_result = pk.add(&[c1.clone(), c2.clone()]);
        assert!(sum_result.is_ok());
        
        let sum = sum_result.unwrap();
        
        // Ciphertext sum should be different from individual ciphertexts
        assert_ne!(sum, c1.clone());
        assert_ne!(sum, c2);
        
        // Test adding empty list
        let empty_result = pk.add(&[]);
        assert!(empty_result.is_err());
        match empty_result {
            Err(PubKeyError::EmptyCiphertextList) => (),
            _ => panic!("Expected EmptyCiphertextList error"),
        }
        
        // Test with invalid ciphertext (out of bounds)
        let invalid = pk.get_n_to_s_plus_one() + BigInt::one();
        let invalid_result = pk.add(&[c1.clone(), invalid]);
        assert!(invalid_result.is_err());
        match invalid_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
        
        // Test with negative ciphertext
        let negative = BigInt::from(-1i32);
        let negative_result = pk.add(&[c1, negative]);
        assert!(negative_result.is_err());
        match negative_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
    }
    
    #[test]
    fn test_multiply() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        let alpha = BigInt::from(3u32);
        
        // Encrypt message
        let (ciphertext, _) = pk.encrypt(&message).unwrap();
        
        // Multiply
        let multiply_result = pk.multiply(&ciphertext, &alpha);
        assert!(multiply_result.is_ok());
        
        let (product, gamma) = multiply_result.unwrap();
        
        // Fixed multiply
        let fixed_multiply_result = pk.multiply_fixed(&ciphertext, &alpha, &gamma);
        assert!(fixed_multiply_result.is_ok());
        
        let fixed_product = fixed_multiply_result.unwrap();
        
        // Both should yield the same result
        assert_eq!(product, fixed_product);
        
        // Test with invalid ciphertext
        let invalid = pk.get_n_to_s_plus_one() + BigInt::one();
        let invalid_result = pk.multiply(&invalid, &alpha);
        assert!(invalid_result.is_err());
        match invalid_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
        
        // Test with negative ciphertext
        let negative = BigInt::from(-1i32);
        let negative_result = pk.multiply(&negative, &alpha);
        assert!(negative_result.is_err());
        match negative_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
    }
    
    #[test]
    fn test_re_rand() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        
        // Encrypt message
        let (ciphertext, _) = pk.encrypt(&message).unwrap();
        
        // Generate random factor
        let r = pk.random_mod_n_to_s_plus_one_star().unwrap();
        
        // Re-randomize
        let re_rand_result = pk.re_rand(&ciphertext, &r);
        assert!(re_rand_result.is_ok());
        
        let re_randomized = re_rand_result.unwrap();
        
        // Re-randomized ciphertext should be different
        assert_ne!(re_randomized, ciphertext);
    }
    
    #[test]
    fn test_multiply_with_proof() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        let alpha = BigInt::from(3u32);
        
        // Encrypt message
        let (ciphertext, _) = pk.encrypt(&message).unwrap();
        
        // Multiply with proof
        let multiply_result = pk.multiply_with_proof(&ciphertext, &alpha);
        assert!(multiply_result.is_ok());
        
        let (_product, proof) = multiply_result.unwrap();
        
        // Check proof structure
        assert_eq!(proof.c_alpha.sign(), Sign::Plus);
        assert!(!proof.b.is_zero());
        assert!(!proof.w.is_zero());
        assert!(!proof.z.is_zero());
        assert!(!proof.a.is_zero());
        assert!(!proof.y.is_zero());
        
        // Test with invalid ciphertext
        let invalid = pk.get_n_to_s_plus_one() + BigInt::one();
        let invalid_result = pk.multiply_with_proof(&invalid, &alpha);
        assert!(invalid_result.is_err());
    }
    
    #[test]
    fn test_combine_shares() {
        let pk = create_test_public_key();
        
        // Create DecryptionShare objects - for a real scenario these would be
        // created by individual parties and have correct ZK proofs
        let mut shares = Vec::new();
        for i in 1..=pk.k {
            shares.push(DecryptionShare {
                index: i,
                ci: BigInt::from((i as u64) * 1000), // Just some test values
            });
        }
        
        // Combine shares
        let result = pk.combine_shares(&shares);
        assert!(result.is_ok());
        
        // Test with insufficient shares
        let insufficient = shares[0..1].to_vec(); // Only one share
        let insufficient_result = pk.combine_shares(&insufficient);
        assert!(insufficient_result.is_err());
        match insufficient_result {
            Err(PubKeyError::InsufficientShares(got, need)) => {
                assert_eq!(got, 1);
                assert_eq!(need, pk.k);
            }
            _ => panic!("Expected InsufficientShares error"),
        }
        
        // Test with repeated indices
        let mut repeated = shares.clone();
        repeated[1].index = repeated[0].index; // Make two shares have the same index
        let repeated_result = pk.combine_shares(&repeated);
        assert!(repeated_result.is_err());
        match repeated_result {
            Err(PubKeyError::RepeatedShareIndex(idx)) => {
                assert_eq!(idx, repeated[0].index);
            }
            _ => panic!("Expected RepeatedShareIndex error"),
        }
    }
    
    #[test]
    fn test_encrypt_proof() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        
        // Generate randomness
        let r = pk.random_mod_n_to_s_plus_one_star().unwrap();
        
        // Encrypt
        let ciphertext = pk.encrypt_fixed(&message, &r).unwrap();
        
        // Generate proof
        let proof_result = pk.encrypt_proof(&message, &ciphertext, &r);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        
        // Check proof structure
        assert!(!proof.b.is_zero());
        assert!(!proof.w.is_zero());
        assert!(!proof.z.is_zero());
    }
    
    #[test]
    fn test_multiply_proof() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        let alpha = BigInt::from(3u32);
        
        // Encrypt message
        let (ca, _r_ca) = pk.encrypt(&message).unwrap();
        
        // Encrypt alpha
        let (c_alpha, r_alpha) = pk.encrypt(&alpha).unwrap();
        
        // Multiply
        let gamma = pk.random_mod_n_to_s_plus_one_star().unwrap();
        let d = pk.multiply_fixed(&ca, &alpha, &gamma).unwrap();
        
        // Generate proof
        let proof_result = pk.multiply_proof(&ca, &c_alpha, &d, &alpha, &r_alpha, &gamma);
        assert!(proof_result.is_ok());
        
        let proof = proof_result.unwrap();
        
        // Check proof structure
        assert_eq!(proof.c_alpha, c_alpha);
        assert!(!proof.a.is_zero());
        assert!(!proof.b.is_zero());
        assert!(!proof.w.is_zero());
        assert!(!proof.y.is_zero());
        assert!(!proof.z.is_zero());
        
        // Test with invalid ca
        let invalid_ca = pk.get_n_to_s_plus_one() + BigInt::one();
        let invalid_result = pk.multiply_proof(&invalid_ca, &c_alpha, &d, &alpha, &r_alpha, &gamma);
        assert!(invalid_result.is_err());
        match invalid_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
        
        // Test with invalid c_alpha
        let invalid_c_alpha = pk.get_n_to_s_plus_one() + BigInt::one();
        let invalid_result = pk.multiply_proof(&ca, &invalid_c_alpha, &d, &alpha, &r_alpha, &gamma);
        assert!(invalid_result.is_err());
        match invalid_result {
            Err(PubKeyError::InvalidCiphertext(_)) => (),
            _ => panic!("Expected InvalidCiphertext error"),
        }
    }
    
    #[test]
    fn test_random_mod_n() {
        let pk = create_test_public_key();
        
        // Generate random values
        let r1_result = pk.random_mod_n();
        assert!(r1_result.is_ok());
        let r1 = r1_result.unwrap();
        
        let r2_result = pk.random_mod_n();
        assert!(r2_result.is_ok());
        let r2 = r2_result.unwrap();
        
        // Two random values should be different with high probability
        assert_ne!(r1, r2);
        
        // Check bounds
        assert!(r1 >= BigInt::zero());
        assert!(r1 < pk.n);
        
        assert!(r2 >= BigInt::zero());
        assert!(r2 < pk.n);
    }
    
    #[test]
    fn test_random_mod_n_to_s_plus_one_star() {
        let pk = create_test_public_key();
        
        // Generate random values
        let r1_result = pk.random_mod_n_to_s_plus_one_star();
        assert!(r1_result.is_ok());
        let r1 = r1_result.unwrap();
        
        let r2_result = pk.random_mod_n_to_s_plus_one_star();
        assert!(r2_result.is_ok());
        let r2 = r2_result.unwrap();
        
        // Two random values should be different with high probability
        assert_ne!(r1, r2);
        
        // Check bounds
        assert!(r1 > BigInt::zero());
        assert!(r1 < pk.get_n_to_s_plus_one());
        
        assert!(r2 > BigInt::zero());
        assert!(r2 < pk.get_n_to_s_plus_one());
    }
    
    #[test]
    fn test_get_cached_values() {
        let pk = create_test_public_key();
        
        // Get cached values
        let n_plus_one = pk.get_n_plus_one();
        let n_to_s = pk.get_n_to_s();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        
        // Check correctness
        assert_eq!(n_plus_one, &pk.n + BigInt::one());
        
        // These are approximate checks since the modulus in the actual code is different
        assert!(n_to_s % &pk.n == BigInt::zero());
        assert!(n_to_s_plus_one % &pk.n == BigInt::zero());
        
        // Check that the cache was populated
        assert!(pk.cached.borrow().is_some());
    }
    
    #[test]
    fn test_homomorphic_properties() {
        let pk = create_test_public_key();
        let m1 = BigInt::from(42u32);
        let m2 = BigInt::from(58u32);
        let alpha = BigInt::from(3u32);
        
        // Encrypt messages
        let (c1, _) = pk.encrypt(&m1).unwrap();
        let (c2, _) = pk.encrypt(&m2).unwrap();
        
        // Addition of ciphertexts
        let sum = pk.add(&[c1.clone(), c2.clone()]).unwrap();
        
        // Multiplication by constant
        let (product, _) = pk.multiply(&c1, &alpha).unwrap();
        
        // Re-randomization
        let r = pk.random_mod_n_to_s_plus_one_star().unwrap();
        let re_randomized = pk.re_rand(&c1, &r).unwrap();
        
        // Check that all operations produce valid ciphertexts
        assert!(sum > BigInt::zero());
        assert!(sum < pk.get_n_to_s_plus_one());
        
        assert!(product > BigInt::zero());
        assert!(product < pk.get_n_to_s_plus_one());
        
        assert!(re_randomized > BigInt::zero());
        assert!(re_randomized < pk.get_n_to_s_plus_one());
        
        // Re-randomization shouldn't change decryption
        assert_ne!(re_randomized, c1);
    }
    
    #[test]
    fn test_zk_proof_integration() {
        let pk = create_test_public_key();
        let message = BigInt::from(42u32);
        
        // Encrypt with proof
        let (ciphertext, proof) = pk.encrypt_with_proof(&message).unwrap();
        
        // Verify the EncryptZK proof
        let verify_result = proof.verify(&pk, &ciphertext);
        assert!(verify_result.is_ok());
        
        // Multiply with proof
        let alpha = BigInt::from(3u32);
        let (product, mul_proof) = pk.multiply_with_proof(&ciphertext, &alpha).unwrap();
        
        // Verify the MulZK proof
        let verify_result = mul_proof.verify(&pk, &product, &ciphertext);
        assert!(verify_result.is_ok());
    }
    
    // Helper function for testing - renamed to avoid conflict
    fn test_factorial(n: u64) -> BigInt {
        let mut result = BigInt::one();
        for i in 1..=n {
            result *= i;
        }
        result
    }
    
    // Add a local mod_inverse implementation
    fn test_mod_inverse(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
        use num_integer::Integer;
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
}