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

