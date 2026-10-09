// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::gf256::GF256;
use fastcrypto::error::FastCryptoResult;
use itertools::Itertools;
use std::iter::{Product, Sum};
use std::ops::{Add, Div, Mul};
use std::{unreachable, vec};

/// This represents a polynomial over the Galois Field GF256.
/// See [gf256](crate::gf256) for more details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial(Vec<GF256>);

impl Polynomial {
    /// Create a polynomial from its coefficients, constant term first.
    pub fn new(coefficients: Vec<GF256>) -> Self {
        Self(coefficients).strip_trailing_zeros()
    }

    /// Returns the degree of this polynomial. Returns 0 for the zero polynomial.
    pub fn degree(&self) -> usize {
        if self.0.is_empty() {
            return 0;
        }
        self.0.len() - 1
    }

    /// Evaluate this polynomial at a given point <i>x</i>.
    pub fn evaluate(&self, x: &GF256) -> GF256 {
        // Horner's method to evaluate the polynomial at x
        self.0
            .iter()
            .rev()
            .fold(GF256::zero(), |sum, coefficient| &(&sum * x) + coefficient)
    }

    /// Return the zero polynomial.
    pub fn zero() -> Self {
        Self(vec![])
    }

    /// Return the one polynomial.
    pub fn one() -> Self {
        Self(vec![GF256::one()])
    }

    /// Strip trailing zeros to create a unique representation of the polynomial.
    fn strip_trailing_zeros(mut self) -> Self {
        while self.0.last() == Some(&GF256::zero()) {
            self.0.pop();
        }
        self
    }

    /// Return a polynomial of the form x + constant
    fn monic_linear(constant: GF256) -> Self {
        Self(vec![constant, GF256::one()])
    }

    /// Create a polynomial `p` given a set of `points` such that `p(x) = y` for all `(x,y)` in `points`.
    /// The degree will be at most points.len() - 1.
    /// It is assumed that the x-values are distinct, otherwise the function will panic.
    pub fn interpolate(points: &[(GF256, GF256)]) -> Self {
        // Lagrangian interpolation, see e.g. https://en.wikipedia.org/wiki/Lagrange_polynomial
        points
            .iter()
            .enumerate()
            .map(|(j, (x_j, y_j))| {
                points
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != j)
                    .map(|(_, (x_i, _))| {
                        (Self::monic_linear(-x_i) / &(x_j - x_i)).expect("Divisor is never zero")
                    })
                    .product::<Polynomial>()
                    * y_j
            })
            .sum()
    }
}

impl Add for &Polynomial {
    type Output = Polynomial;

    fn add(self, other: &Polynomial) -> Self::Output {
        Polynomial(
            self.0
                .iter()
                .zip_longest(other.0.iter())
                .map(|p| match p.left_and_right() {
                    (Some(a), Some(b)) => a + b,
                    (Some(a), None) => *a,
                    (None, Some(b)) => *b,
                    _ => unreachable!(),
                })
                .collect(),
        )
        .strip_trailing_zeros()
    }
}

impl Sum for Polynomial {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Polynomial::zero(), |sum, term| &sum + &term)
    }
}

impl Mul<&GF256> for Polynomial {
    type Output = Polynomial;

    fn mul(self, s: &GF256) -> Self::Output {
        Polynomial(self.0.into_iter().map(|a| &a * s).collect()).strip_trailing_zeros()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Mul for &Polynomial {
    type Output = Polynomial;

    fn mul(self, other: &Polynomial) -> Self::Output {
        if self.0.is_empty() || other.0.is_empty() {
            return Polynomial::zero();
        }
        let degree = self.degree() + other.degree();
        Polynomial(
            (0..=degree)
                .map(|i| {
                    (i.saturating_sub(other.degree())..=i.min(self.degree()))
                        .map(|j| &self.0[j] * &other.0[i - j])
                        .sum()
                })
                .collect(),
        )
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&GF256> for Polynomial {
    type Output = FastCryptoResult<Polynomial>;

    fn div(self, divisor: &GF256) -> Self::Output {
        let inverse = (&GF256::one() / divisor)?;
        Ok(Polynomial(self.0.iter().map(|a| a * &inverse).collect()).strip_trailing_zeros())
    }
}

impl Product for Polynomial {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::one(), |product, factor| &product * &factor)
    }
}

#[cfg(test)]
mod tests {
    use crate::gf256::GF256;
    use crate::polynomial::Polynomial;

    #[test]
    fn test_polynomial_evaluation() {
        let x = GF256::from(2);
        let c = [GF256::from(1), GF256::from(2), GF256::from(3)];
        let result = Polynomial(c.to_vec()).evaluate(&x);
        assert_eq!(
            [
                c[0],
                [c[1], x].into_iter().product(),
                [c[2], x, x].into_iter().product()
            ]
            .into_iter()
            .sum::<GF256>(),
            result
        );
    }

    #[test]
    fn test_arithmetic() {
        let p1 = Polynomial(vec![GF256::from(1), GF256::from(2), GF256::from(3)]);
        let p2 = Polynomial(vec![GF256::from(4), GF256::from(5)]);
        let p3 = Polynomial(vec![GF256::from(2)]);
        assert_eq!(
            &p1 + &p2,
            Polynomial(vec![GF256::from(5), GF256::from(7), GF256::from(3)])
        );
        assert_eq!(
            &p1 * &p3,
            Polynomial(vec![GF256::from(2), GF256::from(4), GF256::from(6)])
        );
        assert_eq!(
            &p1 * &p2,
            Polynomial(vec![
                GF256::from(4),
                GF256::from(13),
                GF256::from(6),
                GF256::from(15)
            ])
        );
    }

    #[test]
    fn test_zero_polynomial() {
        let zero = Polynomial::zero();
        let p = Polynomial(vec![GF256::from(1), GF256::from(2), GF256::from(3)]);
        assert_eq!(zero.degree(), 0);
        assert_eq!(&zero * &p, zero);
        assert_eq!(&p * &zero, zero);
        assert_eq!(&zero * &zero, zero);
        assert_eq!(&zero + &p, p);
        assert_eq!(p.clone() * &GF256::zero(), zero);
    }

    #[test]
    fn test_interpolation() {
        let x = [GF256::from(1), GF256::from(2), GF256::from(3)];
        let y = [GF256::from(7), GF256::from(11), GF256::from(17)];
        let points = x
            .iter()
            .zip(y.iter())
            .map(|(x, y)| (*x, *y))
            .collect::<Vec<_>>();

        let p = Polynomial::interpolate(&points);

        assert!(p.degree() <= points.len());
        for (x, y) in points {
            assert_eq!(y, p.evaluate(&x));
        }
    }
}
