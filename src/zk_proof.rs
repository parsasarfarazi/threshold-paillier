use crypto_bigint::{modular::ConstMontyForm, NonZero, U2048};
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
        let cache = pk.cache();
        let n_plus_one = &cache.n_plus_one;
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        let n_to_s = &cache.n_to_s;

        // Convert to crypto-bigint
        let n_plus_one_uint = U2048::try_from_be_slice(&n_plus_one.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let n_to_s_plus_one_uint = U2048::try_from_be_slice(&n_to_s_plus_one.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let n_to_s_uint = U2048::try_from_be_slice(&n_to_s.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let c_uint = U2048::try_from_be_slice(&c.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let w_uint = U2048::try_from_be_slice(&self.w.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let z_uint = U2048::try_from_be_slice(&self.z.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let b_uint = U2048::try_from_be_slice(&self.b.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;

        // Compute e = SHA256(c, B)
        let mut hash = Sha256::new();
        hash.update(c.to_bytes_le());
        hash.update(&self.b.to_bytes_le());
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);
        let e_uint = U2048::try_from_be_slice(&e.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;

        // Left: (n+1)^W * Z^n mod n^(s+1)
        let n_to_s_plus_one_nz = NonZero::new(n_to_s_plus_one_uint).unwrap();
        let n_plus_one_monty = ConstMontyForm::new(&n_plus_one_uint, n_to_s_plus_one_nz);
        let z_monty = ConstMontyForm::new(&z_uint, n_to_s_plus_one_nz);
        let n_plus_one_to_w = n_plus_one_monty.pow(&w_uint);
        let z_to_n = z_monty.pow(&n_to_s_uint);
        let left = (n_plus_one_to_w * z_to_n).retrieve();

        // Right: B * C^E mod n^(s+1)
        let c_monty = ConstMontyForm::new(&c_uint, n_to_s_plus_one_nz);
        let c_to_e = c_monty.pow(&e_uint);
        let right = (b_uint * c_to_e.retrieve()) % n_to_s_plus_one_uint;

        if left != right {
            return Err(ZKProofError::VerificationFailed);
        }
        Ok(())
    }
}

impl MulZK {
    pub fn verify(&self, pk: &PublicKey, d: &BigInt, ca: &BigInt) -> Result<(), ZKProofError> {
        let cache = pk.cache();
        let n_plus_one = &cache.n_plus_one;
        let n_to_s_plus_one = &cache.n_to_s_plus_one;
        let n_to_s = &cache.n_to_s;

        // Convert to crypto-bigint
        let n_plus_one_uint = U2048::try_from_be_slice(&n_plus_one.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let n_to_s_plus_one_uint = U2048::try_from_be_slice(&n_to_s_plus_one.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let n_to_s_uint = U2048::try_from_be_slice(&n_to_s.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let ca_uint = U2048::try_from_be_slice(&ca.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let c_alpha_uint = U2048::try_from_be_slice(&self.c_alpha.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let d_uint = U2048::try_from_be_slice(&d.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let w_uint = U2048::try_from_be_slice(&self.w.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let y_uint = U2048::try_from_be_slice(&self.y.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let z_uint = U2048::try_from_be_slice(&self.z.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let a_uint = U2048::try_from_be_slice(&self.a.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let b_uint = U2048::try_from_be_slice(&self.b.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;

        // Compute e = SHA256(ca, CAlpha, d, A, B)
        let mut hash = Sha256::new();
        hash.update(ca.to_bytes_le());
        hash.update(&self.c_alpha.to_bytes_le());
        hash.update(d.to_bytes_le());
        hash.update(&self.a.to_bytes_le());
        hash.update(&self.b.to_bytes_le());
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);
        let e_uint = U2048::try_from_be_slice(&e.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;

        // First check: (n+1)^W * Z^n mod n^(s+1) == B * CAlpha^E mod n^(s+1)
        let n_to_s_plus_one_nz = NonZero::new(n_to_s_plus_one_uint).unwrap();
        let n_plus_one_monty = ConstMontyForm::new(&n_plus_one_uint, n_to_s_plus_one_nz);
        let z_monty = ConstMontyForm::new(&z_uint, n_to_s_plus_one_nz);
        let c_alpha_monty = ConstMontyForm::new(&c_alpha_uint, n_to_s_plus_one_nz);
        let n_plus_one_to_w = n_plus_one_monty.pow(&w_uint);
        let z_to_n_to_s = z_monty.pow(&n_to_s_uint);
        let zk1 = (n_plus_one_to_w * z_to_n_to_s).retrieve();
        let c_to_e = c_alpha_monty.pow(&e_uint);
        let zk2 = (b_uint * c_to_e.retrieve()) % n_to_s_plus_one_uint;

        if zk1 != zk2 {
            return Err(ZKProofError::VerificationFailed);
        }

        // Second check: ca^W * Y^n mod n^(s+1) == A * d^E mod n^(s+1)
        let ca_monty = ConstMontyForm::new(&ca_uint, n_to_s_plus_one_nz);
        let y_monty = ConstMontyForm::new(&y_uint, n_to_s_plus_one_nz);
        let d_monty = ConstMontyForm::new(&d_uint, n_to_s_plus_one_nz);
        let ca_to_w = ca_monty.pow(&w_uint);
        let y_to_n_to_s = y_monty.pow(&n_to_s_uint);
        let zk3 = (ca_to_w * y_to_n_to_s).retrieve();
        let d_to_e = d_monty.pow(&e_uint);
        let zk4 = (a_uint * d_to_e.retrieve()) % n_to_s_plus_one_uint;

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
        let cache = pk.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;

        // Convert to crypto-bigint
        let n_to_s_plus_one_uint = U2048::try_from_be_slice(&n_to_s_plus_one.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let c_uint = U2048::try_from_be_slice(&c.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let ci_uint = U2048::try_from_be_slice(&ds.ci.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let v_uint = U2048::try_from_be_slice(&self.v.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let vi_uint = U2048::try_from_be_slice(&self.vi.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let z_uint = U2048::try_from_be_slice(&self.z.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;
        let e_uint = U2048::try_from_be_slice(&self.e.to_bytes_be())
            .ok_or_else(|| ZKProofError::VerificationFailed)?;

        // Compute c^4, ci^2
        let n_to_s_plus_one_nz = NonZero::new(n_to_s_plus_one_uint).unwrap();
        let c_monty = ConstMontyForm::new(&c_uint, n_to_s_plus_one_nz);
        let ci_monty = ConstMontyForm::new(&ci_uint, n_to_s_plus_one_nz);
        let c_to_4 = c_monty.pow(&U2048::from(4u64));
        let ci_to_2 = ci_monty.pow(&U2048::from(2u64));

        // Compute a = c^4^Z * ci^(-2E) mod n^(s+1)
        let c_to_4z = c_to_4.pow(&z_uint);
        let minus_e = -e_uint;
        let minus_two_e = minus_e * U2048::from(2u64);
        let ci_to_minus_2e = ci_monty.pow(&minus_two_e);
        let a = (c_to_4z * ci_to_minus_2e).retrieve();

        // Compute b = V^Z * Vi^(-E) mod n^(s+1)
        let v_monty = ConstMontyForm::new(&v_uint, n_to_s_plus_one_nz);
        let vi_monty = ConstMontyForm::new(&vi_uint, n_to_s_plus_one_nz);
        let v_to_z = v_monty.pow(&z_uint);
        let vi_to_minus_e = vi_monty.pow(&minus_e);
        let b = (v_to_z * vi_to_minus_e).retrieve();

        // Compute e' = SHA256(a, b, c^4, ci^2)
        let mut hash = Sha256::new();
        hash.update(a.to_be_bytes());
        hash.update(b.to_be_bytes());
        hash.update(c_to_4.retrieve().to_be_bytes());
        hash.update(ci_to_2.retrieve().to_be_bytes());
        let e_prime_bytes = hash.finalize();
        let e_prime = BigInt::from_bytes_le(Sign::Plus, &e_prime_bytes);

        if e_prime != self.e {
            return Err(ZKProofError::VerificationFailed);
        }
        Ok(())
    }
}
