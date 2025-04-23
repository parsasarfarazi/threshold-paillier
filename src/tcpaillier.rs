use num_bigint::BigInt;
use num_integer;  
use num_traits::{One, Zero};  // Remove Euclid from here
use std::convert::TryFrom;
use thiserror::Error;

use crate::functions::*;
use crate::polynomial::Polynomial;
use crate::pub_key::PublicKey;
use crate::threshold_share::KeyShare;

// Placeholder for constants
const C: u32 = 40; // Prime checking iteration count

#[derive(Debug, Clone)]
pub struct FixedParams {
    p: BigInt,
    p1: BigInt,
    q: BigInt,
    q1: BigInt,
}

impl FixedParams {
    pub fn validate(&self) -> bool {
        let p1_check = &self.p >> 1;
        let q1_check = &self.q >> 1;
        // Use rug for primality testing
        let p_prime = rug::Integer::from_str_radix(&self.p.to_string(), 10)
            .unwrap()
            .is_probably_prime(u32::try_from(C as i32).unwrap())
            != rug::integer::IsPrime::No;
        let q_prime = rug::Integer::from_str_radix(&self.q.to_string(), 10)
            .unwrap()
            .is_probably_prime(u32::try_from(C as i32).unwrap())
            != rug::integer::IsPrime::No;
        let p1_prime = rug::Integer::from_str_radix(&self.p1.to_string(), 10)
            .unwrap()
            .is_probably_prime(u32::try_from(C as i32).unwrap())
            != rug::integer::IsPrime::No;
        let q1_prime = rug::Integer::from_str_radix(&self.q1.to_string(), 10)
            .unwrap()
            .is_probably_prime(u32::try_from(C as i32).unwrap())
            != rug::integer::IsPrime::No;
        p_prime && q_prime && p1_prime && q1_prime && p1_check == self.p1 && q1_check == self.q1
    }
}

#[derive(Error, Debug)]
pub enum NewKeyError {
    #[error("bit size too small: {0} < 64")]
    BitSizeTooSmall(usize),
    #[error("s parameter too small: {0} < 1")]
    STooSmall(u8),
    #[error("l parameter too small: {0} <= 1")]
    LTooSmall(u8),
    #[error("k parameter invalid: {0} <= 0")]
    KTooSmall(u8),
    #[error("k parameter out of range: {0} not in [{1}, {2}]")]
    KOutOfRange(u8, u8, u8),
    #[error("failed to generate safe primes: {0}")]
    SafePrimeGeneration(String),
    #[error("polynomial generation failed: {0}")]
    PolynomialError(String),
    #[error("random integer generation failed: {0}")]
    RandomIntError(String),
    #[error("cryptographic operation failed: {0}")]
    CryptoError(String),
}

pub struct ThresholdPaillier {
    pub pub_key: PublicKey,
    pub key_shares: Vec<KeyShare>,
}

impl ThresholdPaillier {
    pub fn new(bit_size: usize, s: u8, l: u8, k: u8) -> Result<Self, NewKeyError> {
        let p_prime_size = (bit_size + 1) / 2;
        let q_prime_size = bit_size - p_prime_size;

        let (p, p1) = generate_safe_primes(p_prime_size)
            .map_err(|_| NewKeyError::SafePrimeGeneration("failed to generate p".to_string()))?;

        let (q, q1) = loop {
            let (q, q1) = generate_safe_primes(q_prime_size).map_err(|_| {
                NewKeyError::SafePrimeGeneration("failed to generate q".to_string())
            })?;
            if p != q && p != q1 && q != p1 {
                break (q, q1);
            }
        };

        let params = FixedParams { p, p1, q, q1 };
        Self::new_fixed_key(bit_size, s, l, k, &params)
    }

    pub fn new_fixed_key(
        bit_size: usize,
        s: u8,
        l: u8,
        k: u8,
        params: &FixedParams,
    ) -> Result<Self, NewKeyError> {
        // Parameter validation
        if bit_size < 64 {
            return Err(NewKeyError::BitSizeTooSmall(bit_size));
        }
        if s < 1 {
            return Err(NewKeyError::STooSmall(s));
        }
        if l <= 1 {
            return Err(NewKeyError::LTooSmall(l));
        }
        if k <= 0 {
            return Err(NewKeyError::KTooSmall(k));
        }
        let l_half = (l / 2) + 1;
        if k < l_half || k > l {
            return Err(NewKeyError::KOutOfRange(k, l_half, l));
        }

        let s_big = BigInt::from(s);
        let s_plus_one = &s_big + &BigInt::one();

        let n = &params.p * &params.q;
        let m = &params.p1 * &params.q1;
        let nm = &n * &m;
        let n_to_s = n.modpow(&s_big, &nm); // Placeholder: needs n^s mod nil
        let n_to_s_plus_one = n.modpow(&s_plus_one, &nm);

        // Calculate modular inverse
        let m_inv = mod_inverse(&m, &n).ok_or_else(|| {
            NewKeyError::CryptoError("failed to compute modular inverse".to_string())
        })?;
        let d = &m * &m_inv;

        // Generate polynomial
        let poly = Polynomial::new_random(k as usize - 1, &d)
            .map_err(|e| NewKeyError::PolynomialError(e.to_string()))?;

        // Fix for generating v with Shoup heuristic
        let mut r;
        loop {
            r = random_int(4 * bit_size).map_err(|e| NewKeyError::RandomIntError(e.to_string()))?;
            // Fix 1: Use num_integer::gcd with owned values instead of references
            let gcd = num_integer::gcd(r.clone(), n.clone());
            // Fix 2: Compare with owned BigInt::one()
            if gcd == BigInt::one() {
                break;
            }
        }

        let v = mod_pow(&r, &BigInt::from(2), &n_to_s_plus_one);

        let delta = factorial(l as u64);
        let delta_square = &delta * &delta;

        // Calculate constant
        let constant =
            mod_inverse(&(BigInt::from(4) * &delta_square), &n_to_s).ok_or_else(|| {
                NewKeyError::CryptoError("failed to compute constant inverse".to_string())
            })?;

        // Instead of initializing all fields directly, let's create a PublicKey using
        // the fields we can access and then set vi array separately
        // Assuming PublicKey has a constructor for the public fields:
        let mut pub_key = PublicKey::new_uncached(
            n.clone(),
            v.clone(),
            l,
            k,
            s,
            delta.clone(),
            constant.clone(),
        );

        // If there's no constructor, look at pub_key.rs to see if there's a way to
        // initialize PublicKey without directly touching the cached field

        let mut key_shares = Vec::with_capacity(l as usize);
        for index in 0..l {
            let x_index = (index + 1) as u64;
            // Fix 3: Unwrap the Result before passing to mod_pow
            let si = poly.evaluate(&BigInt::from(x_index))
                .map_err(|e| NewKeyError::PolynomialError(e.to_string()))?;
            let si_mod = mod_pow(&si, &BigInt::one(), &nm);

            // Clone si_mod before moving it into KeyShare::new
            key_shares.push(KeyShare::new(pub_key.clone(), index + 1, si_mod.clone()));

            let delta_si = &si_mod * &delta;
            pub_key.vi[index as usize] = v.modpow(&delta_si, &n_to_s_plus_one);
        }

        Ok(ThresholdPaillier {
            pub_key,
            key_shares,
        })
    }
}

// Helper functions
fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    // Extended Euclidean algorithm to find modular inverse
    let (g, x, _) = extended_gcd(a, m);
    if g != BigInt::one() {
        None // Modular inverse doesn't exist
    } else {
        Some((x % m + m) % m) // Ensure the result is positive
    }
}

fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b == &BigInt::zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (g, x, y) = extended_gcd(b, &(a % b));
        (g, y.clone(), x - (a / b) * y)
    }
}

fn mod_pow(base: &BigInt, exp: &BigInt, modulus: &BigInt) -> BigInt {
    base.modpow(exp, modulus)
}



#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Pow;
    use std::str::FromStr;
    
    // Helper function for more concise test code
    fn create_test_params() -> FixedParams {
        // Using smaller primes for testing
        // p and q are safe primes (p = 2p' + 1 where p' is prime)
        // p = 23, p' = 11
        // q = 47, q' = 23
        let p = BigInt::from(23u32);
        let p1 = BigInt::from(11u32);
        let q = BigInt::from(47u32);
        let q1 = BigInt::from(23u32);
        
        FixedParams { p, p1, q, q1 }
    }
    
    #[test]
    fn test_fixed_params_validate() {
        let params = create_test_params();
        assert!(params.validate(), "Valid test parameters should validate");
        
        // Test with invalid params where p1 is not (p-1)/2
        let invalid_params = FixedParams {
            p: BigInt::from(23u32),
            p1: BigInt::from(13u32), // Not (p-1)/2
            q: BigInt::from(47u32),
            q1: BigInt::from(23u32),
        };
        assert!(!invalid_params.validate(), "Invalid parameters should not validate");
    }
    
    #[test]
    fn test_new_with_bit_size_too_small() {
        // Test with bit_size < 64
        let result = ThresholdPaillier::new(32, 1, 3, 2);
        assert!(matches!(result, Err(NewKeyError::BitSizeTooSmall(32))));
    }
    
    #[test]
    fn test_new_with_s_too_small() {
        // Test with s < 1
        let result = ThresholdPaillier::new_fixed_key(64, 0, 3, 2, &create_test_params());
        assert!(matches!(result, Err(NewKeyError::STooSmall(0))));
    }
    
    #[test]
    fn test_new_with_l_too_small() {
        // Test with l <= 1
        let result = ThresholdPaillier::new_fixed_key(64, 1, 1, 1, &create_test_params());
        assert!(matches!(result, Err(NewKeyError::LTooSmall(1))));
    }
    
    #[test]
    fn test_new_with_k_too_small() {
        // Test with k <= 0
        let result = ThresholdPaillier::new_fixed_key(64, 1, 3, 0, &create_test_params());
        assert!(matches!(result, Err(NewKeyError::KTooSmall(0))));
    }
    
    #[test]
    fn test_new_with_k_out_of_range() {
        // Test with k < (l/2) + 1
        // For l = 5, k should be at least 3
        let result = ThresholdPaillier::new_fixed_key(64, 1, 5, 2, &create_test_params());
        assert!(matches!(result, Err(NewKeyError::KOutOfRange(2, 3, 5))));
        
        // Test with k > l
        let result = ThresholdPaillier::new_fixed_key(64, 1, 5, 6, &create_test_params());
        assert!(matches!(result, Err(NewKeyError::KOutOfRange(6, 3, 5))));
    }
    
    #[test]
    fn test_new_fixed_key_success() {
        let params = create_test_params();
        let result = ThresholdPaillier::new_fixed_key(64, 1, 3, 2, &params);
        assert!(result.is_ok(), "Key generation should succeed with valid parameters");
        
        let tp = result.unwrap();
        assert_eq!(tp.pub_key.n, params.p.clone() * params.q.clone());
        assert_eq!(tp.pub_key.l, 3);
        assert_eq!(tp.pub_key.k, 2);
        assert_eq!(tp.pub_key.s, 1);
        assert_eq!(tp.key_shares.len(), 3);
        
        // Check that each key share has correct index
        for i in 0..3 {
            assert_eq!(tp.key_shares[i].index, (i + 1) as u8);
        }
    }
    
    #[test]
    fn test_mod_inverse() {
        // Test with values that have an inverse
        let a = BigInt::from(3u32);
        let m = BigInt::from(11u32);
        let result = mod_inverse(&a, &m);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), BigInt::from(4u32)); // 3 * 4 = 12 ≡ 1 (mod 11)
        
        // Test with values that don't have an inverse (gcd(a,m) != 1)
        let a = BigInt::from(4u32);
        let m = BigInt::from(8u32);
        let result = mod_inverse(&a, &m);
        assert!(result.is_none());
    }
    
    #[test]
    fn test_extended_gcd() {
        // Test with relatively prime numbers
        let a = BigInt::from(35u32);
        let b = BigInt::from(15u32);
        let (g, x, y) = extended_gcd(&a, &b);
        
        // gcd(35, 15) = 5
        assert_eq!(g, BigInt::from(5u32));
        
        // Verify that g = ax + by
        let ax = &a * &x;
        let by = &b * &y;
        assert_eq!(g, ax + by);
        
        // Test with one value being zero
        let a = BigInt::from(15u32);
        let b = BigInt::from(0u32);
        let (g, x, y) = extended_gcd(&a, &b);
        
        // gcd(15, 0) = 15
        assert_eq!(g, BigInt::from(15u32));
        assert_eq!(x, BigInt::one());
        assert_eq!(y, BigInt::zero());
    }
    
    #[test]
    fn test_mod_pow() {
        let base = BigInt::from(4u32);
        let exp = BigInt::from(13u32);
        let modulus = BigInt::from(497u32);
        
        // Calculate 4^13 mod 497 = 445
        let result = mod_pow(&base, &exp, &modulus);
        assert_eq!(result, BigInt::from(445u32));
        
        // Compare with direct modpow method
        let direct_result = base.modpow(&exp, &modulus);
        assert_eq!(result, direct_result);
    }
    
    #[test]
    fn test_key_share_properties() {
        let params = create_test_params();
        let tp = ThresholdPaillier::new_fixed_key(64, 1, 5, 3, &params).unwrap();
        
        // Test that we have the correct number of key shares
        assert_eq!(tp.key_shares.len(), 5);
        
        // Test that each key share has different private share values
        let mut unique_shares = std::collections::HashSet::new();
        for share in &tp.key_shares {
            unique_shares.insert(share.si.clone());
        }
        assert_eq!(unique_shares.len(), 5, "All key shares should have unique values");
        
        // Test that key shares have correct indices
        for i in 0..5 {
            assert_eq!(tp.key_shares[i].index, (i + 1) as u8);
        }
    }
    
    #[test]
    fn test_public_key_properties() {
        let params = create_test_params();
        let tp = ThresholdPaillier::new_fixed_key(64, 1, 3, 2, &params).unwrap();
        let pk = &tp.pub_key;
        
        // Test n = p*q
        assert_eq!(pk.n, params.p.clone() * params.q.clone());
        
        // Test delta = l!
        assert_eq!(pk.delta, factorial(pk.l as u64));
        
        // Test vi values are set and non-zero
        for vi in &pk.vi {
            assert!(!vi.is_zero(), "vi values should not be zero");
        }
        
        // Test constant is set correctly
        let n_to_s = pk.n.clone().pow(pk.s as u32);
        let delta_square = &pk.delta * &pk.delta;
        let expected_constant = mod_inverse(&(BigInt::from(4u32) * delta_square), &n_to_s).unwrap();
        assert_eq!(pk.constant, expected_constant);
    }
    
    #[test]
    fn test_integration_with_large_values() {
        // This tests creation with slightly larger values
        // Not too large to make tests slow, but large enough to test real behavior
        let p = BigInt::from_str("11087").unwrap();  // Safe prime
        let p1 = BigInt::from_str("5543").unwrap();  // (p-1)/2
        let q = BigInt::from_str("7907").unwrap();   // Safe prime
        let q1 = BigInt::from_str("3953").unwrap();  // (q-1)/2
        
        let params = FixedParams { p, p1, q, q1 };
        assert!(params.validate(), "Test parameters should be valid");
        
        let result = ThresholdPaillier::new_fixed_key(64, 1, 3, 2, &params);
        assert!(result.is_ok(), "Key generation should succeed with valid parameters");
    }
    
    #[test]
    fn test_new_with_random_primes() {
        // Test the random prime generation path - this will be slow
        // Using smallest allowed bit size for faster tests
        let result = ThresholdPaillier::new(64, 1, 3, 2);
        if let Err(e) = &result {
            println!("Error generating keys: {:?}", e);
        }
        assert!(result.is_ok(), "Random key generation should succeed");
        
        let tp = result.unwrap();
        assert_eq!(tp.pub_key.l, 3);
        assert_eq!(tp.pub_key.k, 2);
        assert_eq!(tp.pub_key.s, 1);
        assert_eq!(tp.key_shares.len(), 3);
    }
    
    #[test]
    #[ignore] // This test is very slow, so we mark it as ignored by default
    fn test_new_with_realistic_parameters() {
        // Test with more realistic parameters - this will be very slow
        // Only run when explicitly requested
        let result = ThresholdPaillier::new(1024, 1, 5, 3);
        assert!(result.is_ok(), "Random key generation should succeed with realistic parameters");
    }
    
    #[test]
    fn test_end_to_end_key_generation_and_sharing() {
        let params = create_test_params();
        let tp = ThresholdPaillier::new_fixed_key(64, 1, 5, 3, &params).unwrap();
        
        // Verify that the public key components match expectations
        assert_eq!(tp.pub_key.n, params.p * params.q);
        assert_eq!(tp.pub_key.k, 3);
        assert_eq!(tp.pub_key.l, 5);
        assert_eq!(tp.pub_key.s, 1);
        
        // Verify that we have the right number of key shares
        assert_eq!(tp.key_shares.len(), 5);
        
        // Verify that each key share has the correct index
        for i in 0..5 {
            assert_eq!(tp.key_shares[i].index, i as u8 + 1);
            assert_eq!(tp.key_shares[i].pub_key.n, tp.pub_key.n);
        }
        
        // Verify that vi values in the public key are set correctly
        // Each vi should be v^(si * delta) mod n^(s+1)
        let n_to_s_plus_one = tp.pub_key.n.pow(tp.pub_key.s as u32 + 1);
        let delta = tp.pub_key.delta.clone();
        
        for i in 0..5 {
            let expected_vi = tp.pub_key.v.modpow(&(&tp.key_shares[i].si * &delta), &n_to_s_plus_one);
            assert_eq!(tp.pub_key.vi[i], expected_vi);
        }
    }
}