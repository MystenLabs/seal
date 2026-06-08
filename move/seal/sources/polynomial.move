// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::polynomial;

use seal::gf256;
use std::u64::range_do_eq;

#[test_only]
use std::unit_test::assert_eq;

const EIncompatibleInputLengths: u64 = 1;

/// This represents a polynomial over GF(2^8).
/// The first coefficient is the constant term.
public struct Polynomial has copy, drop, store {
    coefficients: vector<u8>,
}

/// Evaluate a polynomial at a given point.
public fun evaluate(p: &Polynomial, x: u8): u8 {
    let (exp, log) = gf256::tables();
    evaluate_t(&exp, &log, p, x)
}

fun evaluate_t(exp: &vector<u8>, log: &vector<u8>, p: &Polynomial, x: u8): u8 {
    if (p.coefficients.is_empty()) {
        return 0
    };
    let n = p.coefficients.length();
    let mut result = p.coefficients[n - 1];
    (n - 1).do!(|i| {
        result = gf256::add(gf256::mul_t(exp, log, result, x), p.coefficients[n - i - 2]);
    });
    result
}

public(package) fun get_constant_term(p: &Polynomial): u8 {
    if (p.coefficients.is_empty()) 0 // zero polynomial
    else p.coefficients[0]
}

/// Returns the degree of this polynomial, ignoring trailing (highest-order) zero
/// coefficients. Returns 0 for the zero polynomial.
public(package) fun degree(p: &Polynomial): u64 {
    let mut nonzero = p.coefficients.find_indices!(|c| *c != 0);
    if (nonzero.is_empty()) 0 else nonzero.pop_back()
}

// Divide a polynomial by the monic linear polynomial x + c.
fun div_by_monic_linear_t(exp: &vector<u8>, log: &vector<u8>, x: &Polynomial, c: u8): Polynomial {
    let n = x.coefficients.length();
    let mut coefficients = vector[];
    if (n > 1) {
        let mut previous = x.coefficients[n - 1];
        coefficients.push_back(previous);
        range_do_eq!(1, n - 2, |i| {
            previous = gf256::sub(x.coefficients[n - i - 1], gf256::mul_t(exp, log, previous, c));
            coefficients.push_back(previous);
        });
        coefficients.reverse();
    };
    Polynomial { coefficients }
}

/// Compute the barycentric weights w_j = 1 / prod_{i != j} (x[j] - x[i]).
/// These depend only on the x values, so the Lagrange interpolation can reuse them across all
/// output polynomials.
fun compute_weights(exp: &vector<u8>, log: &vector<u8>, x: &vector<u8>): vector<u8> {
    let n = x.length();
    vector::tabulate!(n, |j| {
        let mut denominator = 1;
        n.do!(|i| {
            if (i != j) {
                denominator = gf256::mul_t(exp, log, denominator, gf256::sub(x[j], x[i]));
            };
        });
        gf256::div_t(exp, log, 1, denominator)
    })
}

/// Same as interpolate, but the numerator products, \prod_i (x - x_i), and the barycentric weights,
/// 1 / \prod_{i != j} (x[j] - x[i]), are precomputed (both depend only on x).
fun interpolate_with_numerators_t(
    exp: &vector<u8>,
    log: &vector<u8>,
    x: &vector<u8>,
    y: &vector<u8>,
    numerators: &vector<Polynomial>,
    weights: &vector<u8>,
): Polynomial {
    assert!(x.length() == y.length(), EIncompatibleInputLengths);
    let n = x.length();
    let mut sum = Polynomial { coefficients: vector[] };
    n.do!(|j| {
        sum =
            add(
                &sum,
                &scale_t(exp, log, &numerators[j], gf256::mul_t(exp, log, y[j], weights[j])),
            );
    });
    sum
}

/// Compute the numerators of the Lagrange polynomials for the given x values.
fun compute_numerators_t(exp: &vector<u8>, log: &vector<u8>, x: vector<u8>): vector<Polynomial> {
    // The full numerator depends only on x, so we can compute it here
    let full_numerator = x.fold!(Polynomial { coefficients: vector[1] }, |product, x_j| {
        mul_t(exp, log, &product, &monic_linear(&x_j))
    });
    x.map_ref!(|x_j| div_by_monic_linear_t(exp, log, &full_numerator, *x_j))
}

/// Interpolate l polynomials p_1, ..., p_l such that p_i(x_j) = y[j][i] for all i, j.
/// The length of the input vectors must be the same.
/// The length of each vector in y must be the same (equal to the l above).
/// Aborts if the input lengths are not compatible or if the vectors are empty.
public(package) fun interpolate_all(x: &vector<u8>, y: &vector<vector<u8>>): vector<Polynomial> {
    assert!(x.length() == y.length(), EIncompatibleInputLengths);
    let l = y[0].length();
    assert!(y.all!(|yi| yi.length() == l), EIncompatibleInputLengths);

    // Load the field tables once instead of materializing the constants on every field operation.
    let (exp, log) = gf256::tables();

    // The numerators and the barycentric weights depend only on x, so compute them once and reuse
    // them for every one of the l output polynomials.
    let numerators = compute_numerators_t(&exp, &log, *x);
    let weights = compute_weights(&exp, &log, x);

    vector::tabulate!(l, |i| {
        let yi = y.map_ref!(|yj| yj[i]);
        interpolate_with_numerators_t(&exp, &log, x, &yi, &numerators, &weights)
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

fun mul_t(exp: &vector<u8>, log: &vector<u8>, x: &Polynomial, y: &Polynomial): Polynomial {
    if (x.coefficients.is_empty() || y.coefficients.is_empty()) {
        return Polynomial { coefficients: vector[] }
    };
    let coefficients = vector::tabulate!(
        x.coefficients.length() + y.coefficients.length() -  1,
        |i| {
            let mut sum = 0;
            i.do_eq!(|j| {
                if (j < x.coefficients.length() && i - j < y.coefficients.length()) {
                    sum =
                        gf256::add(
                            sum,
                            gf256::mul_t(exp, log, x.coefficients[j], y.coefficients[i - j]),
                        );
                }
            });
            sum
        },
    );
    Polynomial { coefficients }
}

fun scale_t(exp: &vector<u8>, log: &vector<u8>, x: &Polynomial, s: u8): Polynomial {
    Polynomial { coefficients: x.coefficients.map_ref!(|c| gf256::mul_t(exp, log, *c, s)) }
}

/// Return x - c (same as x + c since GF256 is a binary field)
fun monic_linear(c: &u8): Polynomial {
    Polynomial { coefficients: vector[*c, 1] }
}

// === Test-only wrappers ===
// These keep the original (constant-copying) call shapes available for the unit tests below, which
// exercise the arithmetic at small sizes where the table-copy cost is irrelevant.

#[test_only]
fun mul(x: &Polynomial, y: &Polynomial): Polynomial {
    let (exp, log) = gf256::tables();
    mul_t(&exp, &log, x, y)
}

#[test_only]
fun div_by_monic_linear(x: &Polynomial, c: u8): Polynomial {
    let (exp, log) = gf256::tables();
    div_by_monic_linear_t(&exp, &log, x, c)
}

#[test_only]
fun compute_numerators(x: vector<u8>): vector<Polynomial> {
    let (exp, log) = gf256::tables();
    compute_numerators_t(&exp, &log, x)
}

#[test_only]
fun interpolate_with_numerators(
    x: &vector<u8>,
    y: &vector<u8>,
    numerators: &vector<Polynomial>,
): Polynomial {
    let (exp, log) = gf256::tables();
    let weights = compute_weights(&exp, &log, x);
    interpolate_with_numerators_t(&exp, &log, x, y, numerators, &weights)
}

#[test]
fun test_arithmetic() {
    let x = Polynomial { coefficients: vector[1, 2, 3] };
    let y = Polynomial { coefficients: vector[4, 5] };
    let z = Polynomial { coefficients: vector[2] };
    assert_eq!(x.add(&y).coefficients, vector[5, 7, 3]);
    assert_eq!(x.mul(&z).coefficients, vector[2, 4, 6]);
    assert_eq!(x.mul(&y).coefficients, x"040d060f");
}

#[test]
fun test_evaluate() {
    let p = Polynomial { coefficients: vector[1, 2, 3] }; // 3x^2 + 2x + 1

    // Test vector computed externally using https://github.com/jonas-lj/Ruffini/
    assert_eq!(p.evaluate(0), 1);
    assert_eq!(p.evaluate(1), 0);
    assert_eq!(p.evaluate(2), 9);
    assert_eq!(p.evaluate(3), 8);

    // Test zero polynomial
    let p = Polynomial { coefficients: vector[] };
    assert_eq!(p.evaluate(0), 0);

    let p = Polynomial { coefficients: vector[3] };
    assert_eq!(p.evaluate(0), 3);
    assert_eq!(p.evaluate(1), 3);
    assert_eq!(p.evaluate(2), 3);
    assert_eq!(p.evaluate(3), 3);
}

#[test]
fun test_interpolate() {
    let x = vector[1, 2, 3];
    let y = vector[7, 11, 17];
    let p = interpolate_with_numerators(&x, &y, &compute_numerators(x));
    assert_eq!(p.coefficients, x"1d150f");
    x.zip_do!(y, |x, y| assert!(p.evaluate(x) == y));
}

#[test]
fun test_interpolate_all() {
    let x = vector[1, 2, 3];
    let y = vector[vector[7, 8], vector[11, 12], vector[17, 18]];
    let ps = interpolate_all(&x, &y);
    assert_eq!(ps.length(), 2);
    x.zip_do!(y, |x, y| {
        assert_eq!(ps[0].evaluate(x), y[0]);
        assert_eq!(ps[1].evaluate(x), y[1]);
    });
}

#[test]
fun test_div_exact_by_monic_linear() {
    let x = Polynomial { coefficients: vector[1, 2, 3, 4, 5, 6, 7] };
    let monic_linear = monic_linear(&2);
    let y = mul(&x, &monic_linear);
    let z = div_by_monic_linear(&y, 2);
    assert_eq!(z, x);
}
