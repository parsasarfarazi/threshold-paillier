use crate::functions::{random_mod, FunctionError};
use num_bigint::BigInt;
use num_traits::Zero;
use rand::rngs::OsRng;
use rand::RngCore;
use thiserror::Error;

pub struct Polynomial {
    coefficients: Vec<BigInt>,
}

#[derive(Error, Debug)]
pub enum PolynomialError {
    #[error("random number generation failed: {0}")]
    RandomNumberGeneration(String),
    #[error("invalid degree")]
    InvalidDegree,
}

impl Polynomial {
    pub fn new_random(degree: usize, max: &BigInt) -> Result<Self, PolynomialError> {
        let mut rng = OsRng;
        let mut coefficients = Vec::with_capacity(degree + 1);
        for _ in 0..=degree {
            let coeff = random_mod(max, &mut rng)
                .map_err(|e| PolynomialError::RandomNumberGeneration(e.to_string()))?;
            coefficients.push(coeff);
        }
        Ok(Polynomial { coefficients })
    }

    pub fn evaluate(&self, x: &BigInt) -> Result<BigInt, PolynomialError> {
        if self.coefficients.is_empty() {
            return Err(PolynomialError::InvalidDegree);
        }
        let mut result = BigInt::zero();
        let mut x_power = BigInt::from(1);
        for coeff in &self.coefficients {
            result += coeff * &x_power;
            x_power *= x;
        }
        Ok(result)
    }

    pub fn evaluate_with_x_squared(&self, x: &BigInt) -> Result<BigInt, PolynomialError> {
        if self.coefficients.is_empty() {
            return Err(PolynomialError::InvalidDegree);
        }
        let x_squared = x * x;
        let mut result = BigInt::zero();
        let mut x_power = BigInt::from(1);
        for coeff in &self.coefficients {
            result += coeff * &x_power;
            x_power *= &x_squared;
        }
        Ok(result)
    }
}