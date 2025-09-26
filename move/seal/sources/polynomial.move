// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::polynomial;

use seal::gf256;

/// This represents a polynomial over GF(2^8).
/// The first coefficient is the constant term.
public struct Polynomial has copy, drop, store {
    coefficients: vector<u8>,
}

/// Evaluate a polynomial at a given point.
public fun evaluate(p: &Polynomial, x: u8): u8 {
    let mut result = 0;
    let n = p.coefficients.length();
    n.do!(|i| {
        result = gf256::add(gf256::mul(result, x), p.coefficients[n - i - 1]);
    });
    result
}

public(package) fun get_constant_term(p: &Polynomial): u8 {
    if (p.coefficients.is_empty()) 0 // zero polynomial
    else p.coefficients[0]
}

/// Interpolate a polynomial p such that p(x_i) = y[i] for all i.
/// Panics if the lengths of x and y are not the same.
/// Panics if x contains duplicate values.
public(package) fun interpolate(x: &vector<u8>, y: &vector<u8>): Polynomial {
    assert!(x.length() == y.length());
    let n = x.length();
    let mut sum = Polynomial { coefficients: vector[] };
    n.do!(|j| {
        let mut product = Polynomial { coefficients: vector[1] };
        n.do!(|i| {
            if (i != j) {
                product =
                    mul(
                        &product,
                        &div(&monic_linear(&x[i]), gf256::sub(x[j], x[i])),
                    );
            };
        });
        sum = add(&sum, &scale(&product, y[j]));
    });
    sum
}

/// Interpolate l polynomials p_1, ..., p_l such that p_i(x_j) = y[j][i] for all i, j.
/// The length of the input vectors must be the same.
/// The length of each vector in y must be the same (equal to the l above).
public(package) fun interpolate_all(x: &vector<u8>, y: &vector<vector<u8>>): vector<Polynomial> {
    assert!(x.length() == y.length());
    let l = y[0].length();
    assert!(y.all!(|yi| yi.length() == l));
    vector::tabulate!(l, |i| {
        let yi = y.map_ref!(|yj| yj[i]);
        interpolate(x, &yi)
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

fun div(x: &Polynomial, s: u8): Polynomial {
    x.scale(gf256::div(1, s))
}

fun scale(x: &Polynomial, s: u8): Polynomial {
    Polynomial { coefficients: x.coefficients.map_ref!(|c| gf256::mul(*c, s)) }
}

/// Return x - c
fun monic_linear(c: &u8): Polynomial {
    Polynomial { coefficients: vector[gf256::sub(0, *c), 1] }
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
fun test_interpolate() {
    let x = vector[1, 2, 3];
    let y = vector[7, 11, 17];
    let p = interpolate(&x, &y);
    assert!(p.coefficients == x"1d150f");
    x.zip_do!(y, |x, y| assert!(p.evaluate(x) == y));
}
