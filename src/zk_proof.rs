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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functions::{generate_safe_primes, random_int};
    use crate::pub_key::PublicKey;
    use crate::decryption_share::DecryptionShare;
    // Remove RefCell and keep only necessary imports
    use num_traits::{One, Pow, Zero};
    use num_integer::Integer;
    
    // Helper function to create a test public key
    fn create_test_pk() -> PublicKey {
        // Generate small primes for testing
        let bit_size = 512;
        let (p, q) = generate_safe_primes(bit_size).unwrap();
        let n = &p * &q;
        let s: u8 = 1;
        let k: u8 = 3;
        let l: u8 = 5;
        
        // Create a random v
        let r = random_int(bit_size * 4).unwrap();
        // Clone n before using it with pow
        let n_to_s_plus_one = n.clone().pow((s as u32) + 1);
        let v = r.modpow(&BigInt::from(2), &n_to_s_plus_one);
        
        let delta = factorial(l as u64);
        // Clone n again for this use
        let n_to_s = n.clone().pow(s as u32);
        let constant = mod_inverse(&(BigInt::from(4) * &delta * &delta), &n_to_s).unwrap();
        
        // Create PublicKey by calling a constructor instead of direct field access
        let mut pk = PublicKey::new_uncached(
            n,
            v,
            l,
            k,
            s,
            delta,
            constant,
        );
        
        // Initialize vi values for the test
        for i in 0..l as usize {
            pk.vi[i] = BigInt::from(1000 + i);
        }
        
        pk
    }
    
    // Helper functions
    fn factorial(n: u64) -> BigInt {
        if n == 0 {
            return BigInt::one();
        }
        let mut result = BigInt::one();
        for i in 1..=n {
            result *= BigInt::from(i);
        }
        result
    }
    
    fn mod_inverse(a: &BigInt, modulus: &BigInt) -> Option<BigInt> {
        let gcd = a.gcd(modulus);
        if gcd != BigInt::one() {
            return None;
        }
        
        // Fix the extended_gcd usage
        let result = a.extended_gcd(modulus);
        let mut t = result.x;
        if t < BigInt::zero() {
            t += modulus;
        }
        Some(t)
    }

    // Tests for EncryptZK
    #[test]
    fn test_encrypt_zk_verify_success() {
        let pk = create_test_pk();
        let message = BigInt::from(42);
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        
        // Get a random r in Z*_{n^(s+1)}
        let r = random_int(512 * 4).unwrap();
        
        // Create ciphertext c = (1+n)^m * r^n mod n^(s+1)
        let n_plus_one = pk.get_n_plus_one();
        let _n_to_s = pk.get_n_to_s(); // Prefix unused variable with underscore
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a valid ZK proof
        let w = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute B = (1+n)^w * z^n mod n^(s+1)
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof
        let zk_proof = EncryptZK {
            b,
            w,
            z,
        };
        
        // Verify the proof
        let result = zk_proof.verify(&pk, &c);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_encrypt_zk_verify_failure() {
        let pk = create_test_pk();
        let message = BigInt::from(42);
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        
        // Get a random r in Z*_{n^(s+1)}
        let r = random_int(512 * 4).unwrap();
        
        // Create ciphertext c = (1+n)^m * r^n mod n^(s+1)
        let n_plus_one = pk.get_n_plus_one();
        let _n_to_s = pk.get_n_to_s(); // Prefix with underscore
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create an invalid ZK proof with incorrect w
        let w = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute B = (1+n)^w * z^n mod n^(s+1)
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof with tampered w
        let tampered_w = w + BigInt::one();
        let zk_proof = EncryptZK {
            b,
            w: tampered_w,
            z,
        };
        
        // Verification should fail
        let result = zk_proof.verify(&pk, &c);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    #[test]
    fn test_encrypt_zk_tampered_ciphertext() {
        let pk = create_test_pk();
        let message = BigInt::from(42);
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        
        // Get a random r in Z*_{n^(s+1)}
        let r = random_int(512 * 4).unwrap();
        
        // Create ciphertext c = (1+n)^m * r^n mod n^(s+1)
        let n_plus_one = pk.get_n_plus_one();
        let _n_to_s = pk.get_n_to_s(); // Prefix with underscore
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a valid ZK proof
        let w = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute B = (1+n)^w * z^n mod n^(s+1)
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof
        let zk_proof = EncryptZK {
            b,
            w,
            z,
        };
        
        // Tamper with the ciphertext
        let tampered_c = c + BigInt::one();
        
        // Verification should fail with tampered ciphertext
        let result = zk_proof.verify(&pk, &tampered_c);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    // Tests for MulZK
    #[test]
    fn test_mul_zk_verify_success() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for message m
        let m = BigInt::from(7);
        let r = random_int(512 * 4).unwrap();
        let ca = (n_plus_one.modpow(&m, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Multiply by alpha
        let alpha = BigInt::from(6);
        let gamma = random_int(512 * 4).unwrap();
        
        // Create the product ciphertext d = ca^alpha * (1+n)^0 * gamma^n = ca^alpha * gamma^n
        let d = (ca.modpow(&alpha, &n_to_s_plus_one) * gamma.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a valid MulZK proof
        let r_alpha = random_int(512 * 4).unwrap();
        let c_alpha = (n_plus_one.modpow(&alpha, &n_to_s_plus_one) * r_alpha.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        let w = random_int(512).unwrap();
        let y = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute A = ca^w * y^n
        let a = (ca.modpow(&w, &n_to_s_plus_one) * y.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Compute B = (1+n)^w * z^n
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof
        let zk_proof = MulZK {
            c_alpha,
            a,
            b,
            w,
            y,
            z,
        };
        
        // Verify the proof
        let result = zk_proof.verify(&pk, &d, &ca);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_mul_zk_verify_failure_first_check() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for message m
        let m = BigInt::from(7);
        let r = random_int(512 * 4).unwrap();
        let ca = (n_plus_one.modpow(&m, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Multiply by alpha
        let alpha = BigInt::from(6);
        let gamma = random_int(512 * 4).unwrap();
        
        // Create the product ciphertext d = ca^alpha * (1+n)^0 * gamma^n = ca^alpha * gamma^n
        let d = (ca.modpow(&alpha, &n_to_s_plus_one) * gamma.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create an invalid MulZK proof (tampered b value)
        let r_alpha = random_int(512 * 4).unwrap();
        let c_alpha = (n_plus_one.modpow(&alpha, &n_to_s_plus_one) * r_alpha.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        let w = random_int(512).unwrap();
        let y = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute A = ca^w * y^n
        let a = (ca.modpow(&w, &n_to_s_plus_one) * y.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Compute B = (1+n)^w * z^n but tamper with it
        let b = ((n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one) + BigInt::one();
        
        // Create the ZK proof with tampered B
        let zk_proof = MulZK {
            c_alpha,
            a,
            b,
            w,
            y,
            z,
        };
        
        // Verification should fail
        let result = zk_proof.verify(&pk, &d, &ca);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    #[test]
    fn test_mul_zk_verify_failure_second_check() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for message m
        let m = BigInt::from(7);
        let r = random_int(512 * 4).unwrap();
        let ca = (n_plus_one.modpow(&m, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Multiply by alpha
        let alpha = BigInt::from(6);
        let gamma = random_int(512 * 4).unwrap();
        
        // Create the product ciphertext d = ca^alpha * (1+n)^0 * gamma^n = ca^alpha * gamma^n
        let d = (ca.modpow(&alpha, &n_to_s_plus_one) * gamma.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create an invalid MulZK proof (tampered a value)
        let r_alpha = random_int(512 * 4).unwrap();
        let c_alpha = (n_plus_one.modpow(&alpha, &n_to_s_plus_one) * r_alpha.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        let w = random_int(512).unwrap();
        let y = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute A = ca^w * y^n but tamper with it
        let a = ((ca.modpow(&w, &n_to_s_plus_one) * y.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one) + BigInt::one();
        
        // Compute B = (1+n)^w * z^n
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof with tampered A
        let zk_proof = MulZK {
            c_alpha,
            a,
            b,
            w,
            y,
            z,
        };
        
        // Verification should fail
        let result = zk_proof.verify(&pk, &d, &ca);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    #[test]
    fn test_mul_zk_tampered_d() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_to_s = pk.get_n_to_s();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for message m
        let m = BigInt::from(7);
        let r = random_int(512 * 4).unwrap();
        let ca = (n_plus_one.modpow(&m, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Multiply by alpha
        let alpha = BigInt::from(6);
        let gamma = random_int(512 * 4).unwrap();
        
        // Create the product ciphertext d = ca^alpha * (1+n)^0 * gamma^n = ca^alpha * gamma^n
        let d = (ca.modpow(&alpha, &n_to_s_plus_one) * gamma.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a valid MulZK proof
        let r_alpha = random_int(512 * 4).unwrap();
        let c_alpha = (n_plus_one.modpow(&alpha, &n_to_s_plus_one) * r_alpha.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        let w = random_int(512).unwrap();
        let y = random_int(512).unwrap();
        let z = random_int(512).unwrap();
        
        // Compute A = ca^w * y^n
        let a = (ca.modpow(&w, &n_to_s_plus_one) * y.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Compute B = (1+n)^w * z^n
        let b = (n_plus_one.modpow(&w, &n_to_s_plus_one) * z.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create the ZK proof
        let zk_proof = MulZK {
            c_alpha,
            a,
            b,
            w,
            y,
            z,
        };
        
        // Tamper with d
        let tampered_d = d + BigInt::one();
        
        // Verification should fail with tampered d
        let result = zk_proof.verify(&pk, &tampered_d, &ca);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    // Tests for DecryptShareZK
    #[test]
    fn test_decrypt_share_zk_verify_success() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for testing
        let message = BigInt::from(42);
        let r = random_int(512 * 4).unwrap();
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a decryption share
        let index: u8 = 2;
        let si = BigInt::from(123); // Private key share
        let c_delta = c.modpow(&pk.delta, &n_to_s_plus_one);
        let ci = c_delta.modpow(&si, &n_to_s_plus_one);
        let ds = DecryptionShare { index, ci };
        
        // Create a valid DecryptShareZK proof
        let z = random_int(512).unwrap();
        
        // v is pk.v, vi is pk.vi[index-1]
        let v = pk.v.clone();
        let vi = pk.vi[(index - 1) as usize].clone();
        
        // Compute c^4 and ci^2
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);
        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);
        
        // Compute expected values for a and b
        let c_to_4z = c_to_4.modpow(&z, &n_to_s_plus_one);
        let v_to_z = v.modpow(&z, &n_to_s_plus_one);
        
        // Hash a, b, c^4, ci^2
        let mut hash = Sha256::new();
        
        // Create a for hashing
        let a_for_hash = c_to_4z.clone();
        let (_, a_bytes) = a_for_hash.to_bytes_le();
        hash.update(&a_bytes);
        
        // Create b for hashing
        let b_for_hash = v_to_z.clone();
        let (_, b_bytes) = b_for_hash.to_bytes_le();
        hash.update(&b_bytes);
        
        // Add c^4 and ci^2 to hash
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        
        // Get e from the hash
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);
        
        // Create the ZK proof with correct values
        let zk_proof = DecryptShareZK {
            v,
            vi,
            z,
            e,
        };
        
        // Verify the proof
        let result = zk_proof.verify(&pk, &c, &ds);
        assert!(result.is_ok());
    }
    
    #[test]
    fn test_decrypt_share_zk_tampered_e() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for testing
        let message = BigInt::from(42);
        let r = random_int(512 * 4).unwrap();
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a decryption share
        let index: u8 = 2;
        let si = BigInt::from(123); // Private key share
        let c_delta = c.modpow(&pk.delta, &n_to_s_plus_one);
        let ci = c_delta.modpow(&si, &n_to_s_plus_one);
        let ds = DecryptionShare { index, ci };
        
        // Create a valid DecryptShareZK proof but tamper with e
        let z = random_int(512).unwrap();
        
        // v is pk.v, vi is pk.vi[index-1]
        let v = pk.v.clone();
        let vi = pk.vi[(index - 1) as usize].clone();
        
        // Compute c^4 and ci^2
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);
        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);
        
        // Compute expected values for a and b
        let c_to_4z = c_to_4.modpow(&z, &n_to_s_plus_one);
        let v_to_z = v.modpow(&z, &n_to_s_plus_one);
        
        // Hash a, b, c^4, ci^2
        let mut hash = Sha256::new();
        
        // Create a for hashing
        let a_for_hash = c_to_4z.clone();
        let (_, a_bytes) = a_for_hash.to_bytes_le();
        hash.update(&a_bytes);
        
        // Create b for hashing
        let b_for_hash = v_to_z.clone();
        let (_, b_bytes) = b_for_hash.to_bytes_le();
        hash.update(&b_bytes);
        
        // Add c^4 and ci^2 to hash
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        
        // Get e from the hash but tamper with it
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes) + BigInt::one();
        
        // Create the ZK proof with tampered e
        let zk_proof = DecryptShareZK {
            v,
            vi,
            z,
            e,
        };
        
        // Verification should fail
        let result = zk_proof.verify(&pk, &c, &ds);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    #[test]
    fn test_decrypt_share_zk_tampered_ciphertext() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for testing
        let message = BigInt::from(42);
        let r = random_int(512 * 4).unwrap();
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a decryption share
        let index: u8 = 2;
        let si = BigInt::from(123); // Private key share
        let c_delta = c.modpow(&pk.delta, &n_to_s_plus_one);
        let ci = c_delta.modpow(&si, &n_to_s_plus_one);
        let ds = DecryptionShare { index, ci };
        
        // Create a valid DecryptShareZK proof
        let z = random_int(512).unwrap();
        
        // v is pk.v, vi is pk.vi[index-1]
        let v = pk.v.clone();
        let vi = pk.vi[(index - 1) as usize].clone();
        
        // Compute c^4 and ci^2
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);
        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);
        
        // Compute expected values for a and b
        let c_to_4z = c_to_4.modpow(&z, &n_to_s_plus_one);
        let v_to_z = v.modpow(&z, &n_to_s_plus_one);
        
        // Hash a, b, c^4, ci^2
        let mut hash = Sha256::new();
        
        // Create a for hashing
        let a_for_hash = c_to_4z.clone();
        let (_, a_bytes) = a_for_hash.to_bytes_le();
        hash.update(&a_bytes);
        
        // Create b for hashing
        let b_for_hash = v_to_z.clone();
        let (_, b_bytes) = b_for_hash.to_bytes_le();
        hash.update(&b_bytes);
        
        // Add c^4 and ci^2 to hash
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        
        // Get e from the hash
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);
        
        // Create the ZK proof with valid e
        let zk_proof = DecryptShareZK {
            v,
            vi,
            z,
            e,
        };
        
        // Tamper with the ciphertext
        let tampered_c = c + BigInt::one();
        
        // Verification should fail with tampered ciphertext
        let result = zk_proof.verify(&pk, &tampered_c, &ds);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
    
    #[test]
    fn test_decrypt_share_zk_tampered_ci() {
        let pk = create_test_pk();
        let n_to_s_plus_one = pk.get_n_to_s_plus_one();
        let n_plus_one = pk.get_n_plus_one();
        
        // Create a ciphertext for testing
        let message = BigInt::from(42);
        let r = random_int(512 * 4).unwrap();
        let c = (n_plus_one.modpow(&message, &n_to_s_plus_one) * r.modpow(&pk.n, &n_to_s_plus_one)) % &n_to_s_plus_one;
        
        // Create a decryption share
        let index: u8 = 2;
        let si = BigInt::from(123); // Private key share
        let c_delta = c.modpow(&pk.delta, &n_to_s_plus_one);
        let ci = c_delta.modpow(&si, &n_to_s_plus_one);
        let ds = DecryptionShare { index, ci: ci.clone() };
        
        // Create a valid DecryptShareZK proof
        let z = random_int(512).unwrap();
        
        // v is pk.v, vi is pk.vi[index-1]
        let v = pk.v.clone();
        let vi = pk.vi[(index - 1) as usize].clone();
        
        // Compute c^4 and ci^2
        let four = BigInt::from(4u64);
        let two = BigInt::from(2u64);
        let c_to_4 = c.modpow(&four, &n_to_s_plus_one);
        let ci_to_2 = ds.ci.modpow(&two, &n_to_s_plus_one);
        
        // Compute expected values for a and b
        let c_to_4z = c_to_4.modpow(&z, &n_to_s_plus_one);
        let v_to_z = v.modpow(&z, &n_to_s_plus_one);
        
        // Hash a, b, c^4, ci^2
        let mut hash = Sha256::new();
        
        // Create a for hashing
        let a_for_hash = c_to_4z.clone();
        let (_, a_bytes) = a_for_hash.to_bytes_le();
        hash.update(&a_bytes);
        
        // Create b for hashing
        let b_for_hash = v_to_z.clone();
        let (_, b_bytes) = b_for_hash.to_bytes_le();
        hash.update(&b_bytes);
        
        // Add c^4 and ci^2 to hash
        let (_, c_to_4_bytes) = c_to_4.to_bytes_le();
        hash.update(&c_to_4_bytes);
        let (_, ci_to_2_bytes) = ci_to_2.to_bytes_le();
        hash.update(&ci_to_2_bytes);
        
        // Get e from the hash
        let e_bytes = hash.finalize();
        let e = BigInt::from_bytes_le(Sign::Plus, &e_bytes);
        
        // Create the ZK proof with valid e
        let zk_proof = DecryptShareZK {
            v,
            vi,
            z,
            e,
        };
        
        // Create a tampered decryption share with modified ci
        let tampered_ds = DecryptionShare {
            index,
            ci: ci + BigInt::one(),
        };
        
        // Verification should fail with tampered decryption share
        let result = zk_proof.verify(&pk, &c, &tampered_ds);
        assert!(result.is_err());
        assert!(matches!(result, Err(ZKProofError::VerificationFailed)));
    }
}