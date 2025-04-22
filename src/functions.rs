use num_bigint::{BigInt, Sign};
use num_traits::Zero;
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, rand::RandState, Integer};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FunctionError {
    #[error("random number generation failed")]
    RandomNumberGeneration,
    #[error("safe prime generation failed")]
    SafePrimeGeneration,
    #[error("invalid bit length")]
    InvalidBitLength,
}

pub fn random_int(bits: usize) -> Result<BigInt, FunctionError> {
    let max = BigInt::from(1) << bits;
    random_mod(&max, &mut rand::rngs::OsRng)
}

pub fn random_mod(n: &BigInt, rng: &mut impl RngCore) -> Result<BigInt, FunctionError> {
    if n <= &BigInt::zero() {
        return Err(FunctionError::RandomNumberGeneration);
    }
    let mut bytes = vec![0u8; (n.bits() as usize + 7) / 8];
    let mut result;
    loop {
        rng.fill_bytes(&mut bytes);
        result = BigInt::from_bytes_be(Sign::Plus, &bytes);
        if result < *n {
            break;
        }
    }
    Ok(result)
}

pub fn random_mod_minus_one(n: &BigInt, rng: &mut impl RngCore) -> Result<BigInt, FunctionError> {
    random_mod(n, rng)
}

pub fn generate_safe_primes(bit_len: usize) -> Result<(BigInt, BigInt), FunctionError> {
    if bit_len < 2 {
        return Err(FunctionError::InvalidBitLength);
    }
    let bit_len_u32 =
        TryInto::<u32>::try_into(bit_len).map_err(|_| FunctionError::InvalidBitLength)?;
    let mut q = Integer::new();
    let mut p = Integer::new();
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut rand_state = RandState::new();
    rand_state.seed(&Integer::from_digits(&seed, Order::Msf));
    loop {
        q = Integer::random_bits(bit_len_u32 - 1, &mut rand_state).into();
        q = q.next_prime();
        p = Integer::from(&q * 2) + 1;
        if p.is_probably_prime(40) != rug::integer::IsPrime::No {
            let p_bigint = BigInt::from_bytes_be(Sign::Plus, &p.to_digits::<u8>(Order::Msf));
            let q_bigint = BigInt::from_bytes_be(Sign::Plus, &q.to_digits::<u8>(Order::Msf));
            return Ok((p_bigint, q_bigint));
        }
    }
}

pub fn factorial(n: u64) -> BigInt {
    let mut result = BigInt::from(1);
    for i in 1..=n {
        result *= BigInt::from(i);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigInt;

    const TEST_BITLEN: usize = 256;
    const TEST_C: u32 = 40;

    #[test]
    fn test_random_int_different() {
        let rand1 = random_int(TEST_BITLEN).expect("first random number generation failed");
        let rand2 = random_int(TEST_BITLEN).expect("second random number generation failed");
        assert_ne!(rand1, rand2, "random numbers are equal");
    }

    #[test]
    fn test_random_int_bit_size() {
        let rand1 = random_int(TEST_BITLEN).expect("random number generation failed");
        assert!(
            rand1.bits() as usize <= TEST_BITLEN,
            "random number bit length {} exceeds {}",
            rand1.bits(),
            TEST_BITLEN
        );
    }

    #[test]
    fn test_generate_safe_primes() {
        let (p, q) = generate_safe_primes(TEST_BITLEN).expect("safe prime generation failed");
        let p_expected = &q * BigInt::from(2) + BigInt::from(1);
        let p_rug = Integer::from_digits(&p.to_bytes_be().1, Order::Msf);
        let q_rug = Integer::from_digits(&q.to_bytes_be().1, Order::Msf);
        assert!(
            p_rug.is_probably_prime(TEST_C) != rug::integer::IsPrime::No,
            "p is not prime"
        );
        assert!(
            q_rug.is_probably_prime(TEST_C) != rug::integer::IsPrime::No,
            "q is not prime"
        );
        assert_eq!(p, p_expected, "p != 2*q + 1");
    }

    #[test]
    fn test_generate_safe_primes_key_generation() {
        let (_, pr) = generate_safe_primes(TEST_BITLEN).expect("safe prime generation failed");
        let (_, qr) = generate_safe_primes(TEST_BITLEN).expect("safe prime generation failed");
        let m = &pr * &qr;
        let e = BigInt::from(65537);
        let d = e.modinv(&m).expect("modular inverse failed");
        let r = (&d * &e) % &m;
        assert_eq!(
            r,
            BigInt::from(1),
            "safe prime generation failed modular inverse test"
        );
    }

    #[test]
    fn test_factorial() {
        assert_eq!(factorial(0), BigInt::from(1));
        assert_eq!(factorial(1), BigInt::from(1));
        assert_eq!(factorial(5), BigInt::from(120));
    }
}
