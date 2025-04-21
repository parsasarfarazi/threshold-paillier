use crypto_bigint::{modular::ConstMontyForm, NonZero, U2048};
use num_bigint::{BigInt, Sign};
use rand::rngs::OsRng;
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

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct KeyShare {
    pub pub_key: PublicKey,
    pub index: u8,
    pub si: BigInt,
}

#[derive(Debug, Clone)]
pub struct DecryptShareZK {
    pub vi: BigInt,
    pub e: BigInt,
    pub v: BigInt,
    pub z: BigInt,
}

impl KeyShare {
    pub fn partial_decrypt(&self, c: &BigInt) -> Result<DecryptionShare, KeyShareError> {
        let cache = self.pub_key.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;

        if c >= n_to_s_plus_one || c < &BigInt::zero() {
            return Err(KeyShareError::InvalidCiphertext(
                "ciphertext out of bounds".to_string(),
            ));
        }

        // Convert to crypto-bigint for constant-time modpow
        let n_to_s_plus_one_uint = U2048::try_from_be_slice(&n_to_s_plus_one.to_bytes_be())
            .ok_or_else(|| {
                KeyShareError::InvalidCiphertext("n_to_s_plus_one too large".to_string())
            })?;
        let c_uint = U2048::try_from_be_slice(&c.to_bytes_be())
            .ok_or_else(|| KeyShareError::InvalidCiphertext("c too large".to_string()))?;

        let delta_si_2 = (BigInt::from(2) * &self.pub_key.delta * &self.si).modulo(n_to_s_plus_one);
        let delta_si_2_uint = U2048::try_from_be_slice(&delta_si_2.to_bytes_be())
            .ok_or_else(|| KeyShareError::InvalidCiphertext("delta_si_2 too large".to_string()))?;

        let n_to_s_plus_one_nz = NonZero::new(n_to_s_plus_one_uint).unwrap();
        let c_monty = ConstMontyForm::new(&c_uint, n_to_s_plus_one_nz);
        let pd_uint = c_monty.pow(&delta_si_2_uint);
        let pd = BigInt::from_bytes_be(Sign::Plus, &pd_uint.retrieve().to_be_bytes());

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
        let cache = self.pub_key.cache();
        let n_to_s_plus_one = &cache.n_to_s_plus_one;

        let num_bits = (self.pub_key.s as usize + 2) * (self.pub_key.k as usize) + 256; // SHA256 size = 256 bits
        let r =
            random_int(num_bits).map_err(|e| KeyShareError::RandomNumberError(e.to_string()))?;

        // Convert to crypto-bigint for constant-time modpow
        let n_to_s_plus_one_uint = U2048::try_from_be_slice(&n_to_s_plus_one.to_bytes_be())
            .ok_or_else(|| {
                KeyShareError::ProofGenerationError("n_to_s_plus_one too large".to_string())
            })?;
        let c_uint = U2048::try_from_be_slice(&c.to_bytes_be())
            .ok_or_else(|| KeyShareError::ProofGenerationError("c too large".to_string()))?;
        let v_uint = U2048::try_from_be_slice(&self.pub_key.v.to_bytes_be())
            .ok_or_else(|| KeyShareError::ProofGenerationError("v too large".to_string()))?;
        let ci_uint = U2048::try_from_be_slice(&ds.ci.to_bytes_be())
            .ok_or_else(|| KeyShareError::ProofGenerationError("ci too large".to_string()))?;
        let r_uint = U2048::try_from_be_slice(&r.to_bytes_be())
            .ok_or_else(|| KeyShareError::ProofGenerationError("r too large".to_string()))?;

        let n_to_s_plus_one_nz = NonZero::new(n_to_s_plus_one_uint).unwrap();
        let c_monty = ConstMontyForm::new(&c_uint, n_to_s_plus_one_nz);
        let v_monty = ConstMontyForm::new(&v_uint, n_to_s_plus_one_nz);
        let ci_monty = ConstMontyForm::new(&ci_uint, n_to_s_plus_one_nz);

        let c_to_4 = c_monty.pow(&U2048::from(4u64));
        let a = c_to_4.pow(&r_uint);
        let b = v_monty.pow(&r_uint);
        let ci_to_2 = ci_monty.pow(&U2048::from(2u64));

        let mut hash = Sha256::new();
        hash.update(a.retrieve().to_be_bytes());
        hash.update(b.retrieve().to_be_bytes());
        hash.update(c_to_4.retrieve().to_be_bytes());
        hash.update(ci_to_2.retrieve().to_be_bytes());
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);

        let e_si_delta = (&self.si * &e * &self.pub_key.delta).modulo(n_to_s_plus_one);
        let z = (&e_si_delta + &r).modulo(n_to_s_plus_one);

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
