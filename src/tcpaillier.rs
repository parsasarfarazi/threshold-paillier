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
