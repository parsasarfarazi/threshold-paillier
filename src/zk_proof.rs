use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::decryption_share::DecryptionShare;
use crate::pub_key::PublicKey;

#[derive(Error, Debug)]
pub enum ZKProofError {
    #[error("invalid number of verification values: expected {0}, got {1}")]
    InvalidValueCount(usize, usize),
    #[error("invalid verification value type")]
    InvalidValueType,
    #[error("zk proof verification failed")]
    VerificationFailed,
}

#[derive(Debug, Clone)]
pub struct EncryptZK {
    pub b: BigInt,
    pub w: BigInt,
    pub z: BigInt,
}

#[derive(Debug, Clone)]
pub struct MulZK {
    pub c_alpha: BigInt,
    pub a: BigInt,
    pub b: BigInt,
    pub w: BigInt,
    pub y: BigInt,
    pub z: BigInt,
}

#[derive(Debug, Clone)]
pub struct DecryptShareZK {
    pub v: BigInt,
    pub vi: BigInt,
    pub z: BigInt,
    pub e: BigInt,
}

impl EncryptZK {
    pub fn verify(&self, pk: &PublicKey, c: &BigInt) -> Result<(), ZKProofError> {
        // Use getter methods instead of direct field access
        let n_plus_one = pk.get_n_plus_one();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();

        // Compute e = SHA256(c, B)
        let mut hash = Sha256::new();
        let (_, c_bytes) = c.to_bytes_le();
        hash.update(&c_bytes);
        let (_, b_bytes) = self.b.to_bytes_le();
        hash.update(&b_bytes);
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        // Left: (n+1)^W * Z^n mod n^(s+1)
        let n_plus_one_to_w = n_plus_one.modpow(&self.w, &n_to_s_plus_one);
        let z_to_n = self.z.modpow(&n_to_s, &n_to_s_plus_one);
        let left = (n_plus_one_to_w * z_to_n) % &n_to_s_plus_one;

        // Right: B * C^E mod n^(s+1)
        let c_to_e = c.modpow(&e, &n_to_s_plus_one);
        let right = (&self.b * c_to_e) % &n_to_s_plus_one;

        if left != right {
            return Err(ZKProofError::VerificationFailed);
        }
        Ok(())
    }
}

impl MulZK {
    pub fn verify(&self, pk: &PublicKey, d: &BigInt, ca: &BigInt) -> Result<(), ZKProofError> {
        // Use getter methods instead of direct field access
        let n_plus_one = pk.get_n_plus_one();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();

        // Compute e = SHA256(ca, CAlpha, d, A, B)
        let mut hash = Sha256::new();
        let (_, ca_bytes) = ca.to_bytes_le();
        hash.update(&ca_bytes);
        let (_, c_alpha_bytes) = self.c_alpha.to_bytes_le();
        hash.update(&c_alpha_bytes);
        let (_, d_bytes) = d.to_bytes_le();
        hash.update(&d_bytes);
        let (_, a_bytes) = self.a.to_bytes_le();
        hash.update(&a_bytes);
        let (_, b_bytes) = self.b.to_bytes_le();
        hash.update(&b_bytes);
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        // First check: (n+1)^W * Z^n mod n^(s+1) == B * CAlpha^E mod n^(s+1)
        let n_plus_one_to_w = n_plus_one.modpow(&self.w, &n_to_s_plus_one);
        let z_to_n_to_s = self.z.modpow(&n_to_s, &n_to_s_plus_one);
        let zk1 = (n_plus_one_to_w * z_to_n_to_s) % &n_to_s_plus_one;
        
        let c_alpha_to_e = self.c_alpha.modpow(&e, &n_to_s_plus_one);
        let zk2 = (&self.b * c_alpha_to_e) % &n_to_s_plus_one;

        if zk1 != zk2 {
            return Err(ZKProofError::VerificationFailed);
        }

        // Second check: ca^W * Y^n mod n^(s+1) == A * d^E mod n^(s+1)
        let ca_to_w = ca.modpow(&self.w, &n_to_s_plus_one);
        let y_to_n_to_s = self.y.modpow(&n_to_s, &n_to_s_plus_one);
        let zk3 = (ca_to_w * y_to_n_to_s) % &n_to_s_plus_one;
        
        let d_to_e = d.modpow(&e, &n_to_s_plus_one);
        let zk4 = (&self.a * d_to_e) % &n_to_s_plus_one;

        if zk3 != zk4 {
            return Err(ZKProofError::VerificationFailed);
        }
        Ok(())
    }
}

impl DecryptShareZK {
    pub fn verify(
        &self,
        pk: &PublicKey,
        c: &BigInt,
        ds: &DecryptionShare,
    ) -> Result<(), ZKProofError> {
        // Use getter methods instead of direct field access
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();

        // Compute c^4, ci^2
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);
        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);

        // Compute a = c^4^Z * ci^(-2E) mod n^(s+1)
        let c_to_4z = c_to_4.modpow(&self.z, &n_to_s_plus_one);
        
        let minus_two_e = BigInt::from(-2) * &self.e;
        let ci_to_minus_2e = ds.ci.modpow(&minus_two_e, &n_to_s_plus_one);
        let a = (c_to_4z * ci_to_minus_2e) % &n_to_s_plus_one;

        // Compute b = V^Z * Vi^(-E) mod n^(s+1)
        let v_to_z = self.v.modpow(&self.z, &n_to_s_plus_one);
        
        let minus_e = BigInt::from(-1) * &self.e;
        let vi_to_minus_e = self.vi.modpow(&minus_e, &n_to_s_plus_one);
        let b = (v_to_z * vi_to_minus_e) % &n_to_s_plus_one;

        // Compute e' = SHA256(a, b, c^4, ci^2)
        let mut hash = Sha256::new();
        let (_, a_bytes) = a.to_bytes_le();
        hash.update(&a_bytes);
        let (_, b_bytes) = b.to_bytes_le();
        hash.update(&b_bytes);
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        let e_prime_bytes = hash.finalize();
        let e_prime = BigInt::from_bytes_le(Sign::Plus, &e_prime_bytes);

        if e_prime != self.e {
            return Err(ZKProofError::VerificationFailed);
        }
        Ok(())
    }
}