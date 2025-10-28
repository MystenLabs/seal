// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::polynomial;

use seal::gf256;
use std::u64::range_do_eq;

const EIncomatibleInputLengths: u64 = 1;

/// This represents a polynomial over GF(2^8).
/// The first coefficient is the constant term.
public struct Polynomial has copy, drop, store {
    coefficients: vector<u8>,
}

/// Evaluate a polynomial at a given point.
public fun evaluate(p: &Polynomial, x: u8): u8 {
    if (p.coefficients.is_empty()) {
        return 0
    };
    let n = p.coefficients.length();
    let mut result = p.coefficients[n - 1];
    (n - 1).do!(|i| {
        result = gf256::add(gf256::mul(result, x), p.coefficients[n - i - 2]);
    });
    result
}

public(package) fun get_constant_term(p: &Polynomial): u8 {
    if (p.coefficients.is_empty()) 0 // zero polynomial
    else p.coefficients[0]
}

// Divide a polynomial by the monic linear polynomial x + c.
// This assumes that the polynomial is divisible by the monic linear polynomial,
// and it's not clear what the result will be otherwise.
// Aborts if the polynomial is empty.
fun div_exact_by_monic_linear(x: &Polynomial, c: u8): Polynomial {
    let n = x.coefficients.length();
    let mut coefficients = vector::empty();

    let mut previous = x.coefficients[n - 1];
    coefficients.push_back(previous);

    range_do_eq!(1, n - 2, |i| {
        previous = gf256::sub(x.coefficients[n - i - 1], gf256::mul(previous, c));
        coefficients.push_back(previous);
    });
    coefficients.reverse();
    Polynomial { coefficients }
}

/// Same as interpolate, but the numerator product, \prod_i (x - x_i), is precomputed.
fun interpolate_with_numerators(
    x: &vector<u8>,
    y: &vector<u8>,
    numerators: &vector<Polynomial>,
): Polynomial {
    assert!(x.length() == y.length(), EIncomatibleInputLengths);
    let n = x.length();
    let mut sum = Polynomial { coefficients: vector[] };
    n.do!(|j| {
        let mut denominator = 1;
        n.do!(|i| {
            if (i != j) {
                denominator = gf256::mul(denominator, gf256::sub(x[j], x[i]));
            };
        });
        sum =
            add(
                &sum,
                &numerators[j].scale(
                    gf256::div(y[j], denominator),
                ),
            );
    });
    sum
}

/// Compute the numerators of the Lagrange polynomials for the given x values.
fun compute_numerators(x: vector<u8>): vector<Polynomial> {
    // The full numerator depends only on x, so we can compute it here
    let full_numerator = x.fold!(Polynomial { coefficients: vector[1] }, |product, x_j| {
        product.mul(&monic_linear(&x_j))
    });
    x.map_ref!(|x_j| div_exact_by_monic_linear(&full_numerator, *x_j))
}

/// Interpolate l polynomials p_1, ..., p_l such that p_i(x_j) = y[j][i] for all i, j.
/// The length of the input vectors must be the same.
/// The length of each vector in y must be the same (equal to the l above).
/// Aborts if the input lengths are not compatible or if the vectors are empty.
public(package) fun interpolate_all(x: &vector<u8>, y: &vector<vector<u8>>): vector<Polynomial> {
    assert!(x.length() == y.length(), EIncomatibleInputLengths);
    let l = y[0].length();
    assert!(y.all!(|yi| yi.length() == l), EIncomatibleInputLengths);

    // The numerators depend only on x, so we can compute them here
    let numerators = compute_numerators(*x);
    vector::tabulate!(l, |i| {
        let yi = y.map_ref!(|yj| yj[i]);
        interpolate_with_numerators(x, &yi, &numerators)
    })
}

fun add(x: &Polynomial, y: &Polynomial): Polynomial {
    let x_length: u64 = x.coefficients.length();
    let y_length: u64 = y.coefficients.length();
    if (x_length < y_length) {
        // We assume that x is the longer vector
        return y.add(x)
    };
    let coefficients = vector::tabulate!(x_length, |i| {
        if (i < y_length) {
            gf256::add(x.coefficients[i], y.coefficients[i])
        } else {
            x.coefficients[i]
        }
    });

    Polynomial { coefficients }
}

fun mul(x: &Polynomial, y: &Polynomial): Polynomial {
    if (x.coefficients.is_empty() || y.coefficients.is_empty()) {
        return Polynomial { coefficients: vector[] }
    };
    let coefficients = vector::tabulate!(
        x.coefficients.length() + y.coefficients.length() -  1,
        |i| {
            let mut sum = 0;
            i.do_eq!(|j| {
                if (j < x.coefficients.length() && i - j < y.coefficients.length()) {
                    sum = gf256::add(sum, gf256::mul(x.coefficients[j], y.coefficients[i - j]));
                }
            });
            sum
        },
    );
    Polynomial { coefficients }
}

fun scale(x: &Polynomial, s: u8): Polynomial {
    Polynomial { coefficients: x.coefficients.map_ref!(|c| gf256::mul(*c, s)) }
}

/// Return x - c (same as x + c since GF256 is a binary field)
fun monic_linear(c: &u8): Polynomial {
    Polynomial { coefficients: vector[*c, 1] }
}

#[test]
fun test_arithmetic() {
    let x = Polynomial { coefficients: vector[1, 2, 3] };
    let y = Polynomial { coefficients: vector[4, 5] };
    let z = Polynomial { coefficients: vector[2] };
    assert!(x.add(&y).coefficients == vector[5, 7, 3]);
    assert!(x.mul(&z).coefficients == vector[2, 4, 6]);
    assert!(x.mul(&y).coefficients == x"040d060f");
}

#[test]
fun test_evaluate() {
    let p = Polynomial { coefficients: vector[1, 2, 3] }; // 3x^2 + 2x + 1

    // Test vector computed externally using https://github.com/jonas-lj/Ruffini/
    assert!(p.evaluate(0) == 1);
    assert!(p.evaluate(1) == 0);
    assert!(p.evaluate(2) == 9);
    assert!(p.evaluate(3) == 8);

    // Test zero polynomial
    let p = Polynomial { coefficients: vector[] };
    assert!(p.evaluate(0) == 0);

    let p = Polynomial { coefficients: vector[3] };
    assert!(p.evaluate(0) == 3);
    assert!(p.evaluate(1) == 3);
    assert!(p.evaluate(2) == 3);
    assert!(p.evaluate(3) == 3);
}

#[test]
fun test_interpolate() {
    let x = vector[1, 2, 3];
    let y = vector[7, 11, 17];
    let p = interpolate_with_numerators(&x, &y, &compute_numerators(x));
    assert!(p.coefficients == x"1d150f");
    x.zip_do!(y, |x, y| assert!(p.evaluate(x) == y));
}

#[test]
fun test_interpolate_all() {
    let x = vector[1, 2, 3];
    let y = vector[vector[7, 8], vector[11, 12], vector[17, 18]];
    let ps = interpolate_all(&x, &y);
    assert!(ps.length() == 2);
    x.zip_do!(y, |x, y| {
        assert!(ps[0].evaluate(x) == y[0]);
        assert!(ps[1].evaluate(x) == y[1]);
    });
}

#[test]
fun test_div_exact_by_monic_linear() {
    let x = Polynomial { coefficients: vector[1, 2, 3, 4, 5, 6, 7] };
    let monic_linear = monic_linear(&2);
    let y = mul(&x, &monic_linear);
    let z = div_exact_by_monic_linear(&y, 2);
    assert!(z == x);
}
