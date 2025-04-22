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
