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

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::{BigInt, ToBigInt};
    use num_traits::One;

    #[test]
    fn test_create_polynomial() {
        let max = BigInt::from(1000);
        let degree = 3;
        
        // Create polynomial of degree 3
        let poly = Polynomial::new_random(degree, &max).expect("Failed to create polynomial");
        
        // Check that the polynomial has correct number of coefficients (degree + 1)
        assert_eq!(
            poly.coefficients.len(),
            degree + 1,
            "Polynomial should have {} coefficients",
            degree + 1
        );
        
        // Check that all coefficients are within range
        for (i, coeff) in poly.coefficients.iter().enumerate() {
            assert!(
                coeff >= &BigInt::zero() && coeff < &max,
                "Coefficient {} is out of range: {}",
                i,
                coeff
            );
        }
    }
    
    #[test]
    fn test_new_random_with_zero_degree() {
        let max = BigInt::from(1000);
        let degree = 0;
        
        let poly = Polynomial::new_random(degree, &max).expect("Failed to create polynomial");
        
        assert_eq!(
            poly.coefficients.len(),
            1,
            "Polynomial of degree 0 should have 1 coefficient"
        );
    }

    #[test]
    fn test_evaluate_constant_polynomial() {
        // Create a constant polynomial (degree 0) with a specific value
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(42));
        let poly = Polynomial { coefficients };
        
        // Evaluating at any x should return the constant
        let result = poly.evaluate(&BigInt::from(5)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(42));
        
        // Test with another value of x
        let result = poly.evaluate(&BigInt::from(100)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(42));
    }
    
    #[test]
    fn test_evaluate_linear_polynomial() {
        // Create a linear polynomial: 2x + 3
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(3));  // Constant term
        coefficients.push(BigInt::from(2));  // x coefficient
        let poly = Polynomial { coefficients };
        
        // Test evaluation at x = 5: 2*5 + 3 = 13
        let result = poly.evaluate(&BigInt::from(5)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(13));
        
        // Test evaluation at x = 10: 2*10 + 3 = 23
        let result = poly.evaluate(&BigInt::from(10)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(23));
    }
    
    #[test]
    fn test_evaluate_quadratic_polynomial() {
        // Create a quadratic polynomial: 3x^2 + 2x + 1
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(1));  // Constant term
        coefficients.push(BigInt::from(2));  // x coefficient
        coefficients.push(BigInt::from(3));  // x^2 coefficient
        let poly = Polynomial { coefficients };
        
        // Test evaluation at x = 2: 3*2^2 + 2*2 + 1 = 3*4 + 4 + 1 = 12 + 5 = 17
        let result = poly.evaluate(&BigInt::from(2)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(17));
        
        // Test evaluation at x = 5: 3*5^2 + 2*5 + 1 = 3*25 + 10 + 1 = 75 + 11 = 86
        let result = poly.evaluate(&BigInt::from(5)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(86));
    }
    
    #[test]
    fn test_evaluate_with_negative_coefficients() {
        // Create a polynomial with negative coefficients: -2x^2 + 3x - 1
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(-1));  // Constant term
        coefficients.push(BigInt::from(3));   // x coefficient
        coefficients.push(BigInt::from(-2));  // x^2 coefficient
        let poly = Polynomial { coefficients };
        
        // Test evaluation at x = 2: -2*2^2 + 3*2 - 1 = -2*4 + 6 - 1 = -8 + 6 - 1 = -3
        let result = poly.evaluate(&BigInt::from(2)).expect("Failed to evaluate polynomial");
        assert_eq!(result, BigInt::from(-3));
    }
    
    #[test]
    fn test_evaluate_with_large_numbers() {
        // Create a polynomial with large coefficients
        let mut coefficients = Vec::new();
        
        // Add coefficients with large values
        coefficients.push(BigInt::parse_bytes(b"12345678901234567890", 10).unwrap());
        coefficients.push(BigInt::parse_bytes(b"98765432109876543210", 10).unwrap());
        let poly = Polynomial { coefficients };
        
        // Create a large x value
        let x = BigInt::parse_bytes(b"123456789", 10).unwrap();
        
        // Expected result: 12345678901234567890 + 98765432109876543210*123456789
        let expected = BigInt::parse_bytes(b"12345678901234567890", 10).unwrap() +
                      (BigInt::parse_bytes(b"98765432109876543210", 10).unwrap() * 
                       BigInt::parse_bytes(b"123456789", 10).unwrap());
        
        let result = poly.evaluate(&x).expect("Failed to evaluate polynomial");
        assert_eq!(result, expected);
    }

    #[test]
    fn test_evaluate_empty_polynomial() {
        // Create an empty polynomial (invalid)
        let poly = Polynomial { coefficients: Vec::new() };
        
        // Evaluation should fail with InvalidDegree error
        let result = poly.evaluate(&BigInt::from(5));
        assert!(result.is_err());
        
        match result {
            Err(PolynomialError::InvalidDegree) => (),
            _ => panic!("Expected InvalidDegree error"),
        }
    }
    
    #[test]
    fn test_evaluate_with_x_squared_constant() {
        // Create a constant polynomial (degree 0)
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(42));
        let poly = Polynomial { coefficients };
        
        // Even with x-squared, the result should be the constant
        let result = poly.evaluate_with_x_squared(&BigInt::from(5)).expect("Failed to evaluate with x squared");
        assert_eq!(result, BigInt::from(42));
    }
    
    #[test]
    fn test_evaluate_with_x_squared_linear() {
        // Create a linear polynomial: 2x + 3
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(3));  // Constant term
        coefficients.push(BigInt::from(2));  // x coefficient
        let poly = Polynomial { coefficients };
        
        // With x_squared, this becomes 3 + 2*x^2
        // For x=2, result should be 3 + 2*2^2 = 3 + 2*4 = 3 + 8 = 11
        let result = poly.evaluate_with_x_squared(&BigInt::from(2)).expect("Failed to evaluate with x squared");
        assert_eq!(result, BigInt::from(11));
        
        // For x=3, result should be 3 + 2*3^2 = 3 + 2*9 = 3 + 18 = 21
        let result = poly.evaluate_with_x_squared(&BigInt::from(3)).expect("Failed to evaluate with x squared");
        assert_eq!(result, BigInt::from(21));
    }

    #[test]
    fn test_evaluate_with_x_squared_quadratic() {
        // Create a quadratic polynomial: 3x^2 + 2x + 1
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(1));  // Constant term
        coefficients.push(BigInt::from(2));  // x coefficient
        coefficients.push(BigInt::from(3));  // x^2 coefficient
        let poly = Polynomial { coefficients };
        
        // With x_squared, this becomes 1 + 2*x^2 + 3*x^4
        // For x=2, result = 1 + 2*4 + 3*16 = 1 + 8 + 48 = 57
        let result = poly.evaluate_with_x_squared(&BigInt::from(2)).expect("Failed to evaluate with x squared");
        assert_eq!(result, BigInt::from(57));
    }

    #[test]
    fn test_evaluate_with_x_squared_higher_degree() {
        // Create a higher degree polynomial: x^4 + x^3 + x^2 + x + 1
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(1));  // Constant term
        coefficients.push(BigInt::from(1));  // x coefficient
        coefficients.push(BigInt::from(1));  // x^2 coefficient
        coefficients.push(BigInt::from(1));  // x^3 coefficient
        coefficients.push(BigInt::from(1));  // x^4 coefficient
        let poly = Polynomial { coefficients };
        
        // With x_squared, this becomes 1 + x^2 + x^4 + x^6 + x^8
        // For x=2, result = 1 + 4 + 16 + 64 + 256 = 341
        let result = poly.evaluate_with_x_squared(&BigInt::from(2)).expect("Failed to evaluate with x squared");
        assert_eq!(result, BigInt::from(341));
    }

    #[test]
    fn test_evaluate_with_x_squared_empty() {
        // Create an empty polynomial (invalid)
        let poly = Polynomial { coefficients: Vec::new() };
        
        // Evaluation should fail with InvalidDegree error
        let result = poly.evaluate_with_x_squared(&BigInt::from(5));
        assert!(result.is_err());
        
        match result {
            Err(PolynomialError::InvalidDegree) => (),
            _ => panic!("Expected InvalidDegree error"),
        }
    }
    
    #[test]
    fn test_lagrange_basis_polynomial() {
        // Test a simple Lagrange interpolation scenario
        // Create xs = [1, 2, 3]
        let xs = vec![
            BigInt::from(1),
            BigInt::from(2),
            BigInt::from(3),
        ];
        
        // Create a degree 2 polynomial with coefficients [6, 11, 6]
        // p(x) = 6x^2 + 11x + 6
        // Which has p(1) = 23, p(2) = 50, p(3) = 87
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(6));   // Constant term
        coefficients.push(BigInt::from(11));  // x coefficient
        coefficients.push(BigInt::from(6));   // x^2 coefficient
        let poly = Polynomial { coefficients };
        
        // Check that the polynomial evaluates correctly at the points
        let y1 = poly.evaluate(&BigInt::from(1)).unwrap();
        let y2 = poly.evaluate(&BigInt::from(2)).unwrap();
        let y3 = poly.evaluate(&BigInt::from(3)).unwrap();
        
        assert_eq!(y1, BigInt::from(23));
        assert_eq!(y2, BigInt::from(50));
        assert_eq!(y3, BigInt::from(87));
        
        // Now verify that we can interpolate back using Lagrange basis
        // This isn't directly testing our code, but validates the mathematical properties
        // our polynomial would be used for in a secret sharing scheme
        
        // Lagrange basis polynomials for the points (1,23), (2,50), (3,87)
        // L1(x) = (x-2)(x-3)/((1-2)(1-3)) = (x-2)(x-3)/(-2)(-1) = (x-2)(x-3)/2
        // L2(x) = (x-1)(x-3)/((2-1)(2-3)) = (x-1)(x-3)/(1)(-1) = -(x-1)(x-3)
        // L3(x) = (x-1)(x-2)/((3-1)(3-2)) = (x-1)(x-2)/(2)(1) = (x-1)(x-2)/2
        
        // We can use these to verify at a new point, e.g., x=4
        // p(4) = 23*L1(4) + 50*L2(4) + 87*L3(4)
        
        // L1(4) = (4-2)(4-3)/2 = (2)(1)/2 = 1
        // L2(4) = -(4-1)(4-3) = -(3)(1) = -3
        // L3(4) = (4-1)(4-2)/2 = (3)(2)/2 = 3
        
        // p(4) = 23*1 + 50*(-3) + 87*3 = 23 - 150 + 261 = 134
        
        // Directly calculate p(4) using our polynomial
        let p4 = poly.evaluate(&BigInt::from(4)).unwrap();
        assert_eq!(p4, BigInt::from(134));
    }

    #[test]
    fn test_polynomial_consistency() {
        // Test that evaluate and evaluate_with_x_squared are consistent
        // For a polynomial p(x) = a0 + a1*x + a2*x^2 + ... + an*x^n
        // evaluate(x) computes p(x)
        // evaluate_with_x_squared(x) computes a0 + a1*x^2 + a2*x^4 + ... + an*x^(2n)
        // So evaluate_with_x_squared(sqrt(x)) should equal evaluate(x)
        
        // Create a polynomial: 3x^2 + 2x + 1
        let mut coefficients = Vec::new();
        coefficients.push(BigInt::from(1));  // Constant term
        coefficients.push(BigInt::from(2));  // x coefficient
        coefficients.push(BigInt::from(3));  // x^2 coefficient
        let poly = Polynomial { coefficients };
        
        // Evaluate at x = 4: 3*4^2 + 2*4 + 1 = 3*16 + 8 + 1 = 48 + 9 = 57
        let direct_eval = poly.evaluate(&BigInt::from(4)).expect("Failed to evaluate");
        
        // Evaluate with x_squared at x = 2 (sqrt(4)): 1 + 2*(2^2) + 3*(2^4) = 1 + 2*4 + 3*16 = 1 + 8 + 48 = 57
        let squared_eval = poly.evaluate_with_x_squared(&BigInt::from(2)).expect("Failed to evaluate with x squared");
        
        // Both should give the same result
        assert_eq!(direct_eval, squared_eval);
    }
}
