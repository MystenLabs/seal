// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

module seal::polynomial;

use seal::gf256;

/// This represents a polynomial over GF(2^8).
/// The first coefficient is the constant term.
public struct Polynomial has copy, drop, store {
    coefficients: vector<u8>,
}

public(package) fun get_constant_term(p: &Polynomial): u8 {
    if (p.coefficients.is_empty()) {
        return 0
    };
    p.coefficients[0]
}

fun add(x: &Polynomial, y: &Polynomial): Polynomial {
    let x_length: u64 = x.coefficients.length();
    let y_length: u64 = y.coefficients.length();
    if (x_length < y_length) {
        // We assume that x is the longer vector
        return add(y, x)
    };
    let coefficients = vector::tabulate!(x_length, |i| {
        if (i < y_length) {
            gf256::add(x.coefficients[i], y.coefficients[i])
        } else {
            x.coefficients[i]
        }
    });
    let result = Polynomial { coefficients };
    reduce(result);
    result
}

fun degree(x: &Polynomial): u64 {
    x.coefficients.length() - 1
}

fun reduce(mut x: Polynomial) {
    while (x.coefficients.length() > 0 && x.coefficients[x.coefficients.length() - 1] == 0) {
        x.coefficients.pop_back();
    };
}

fun mul(x: &Polynomial, y: &Polynomial): Polynomial {
    let degree = x.degree() + y.degree();

    let coefficients = vector::tabulate!(degree + 1, |i| {
        let mut sum = 0;
        i.do_eq!(|j| {
            if (j <= x.degree() && i - j <= y.degree()) {
                sum = gf256::add(sum, gf256::mul(x.coefficients[j], y.coefficients[i - j]));
            }
        });
        sum
    });
    let result = Polynomial { coefficients };
    reduce(result);
    result
}

fun div(x: &Polynomial, s: u8): Polynomial {
    scale(x, gf256::div(1, s))
}

fun scale(x: &Polynomial, s: u8): Polynomial {
    Polynomial { coefficients: x.coefficients.map_ref!(|c| gf256::mul(*c, s)) }
}

/// Return x - c
fun monic_linear(c: &u8): Polynomial {
    Polynomial { coefficients: vector[gf256::sub(0, *c), 1] }
}

public(package) fun interpolate(x: &vector<u8>, y: &vector<u8>): Polynomial {
    assert!(x.length() == y.length());
    let n = x.length();
    let mut sum = Polynomial { coefficients: vector::empty<u8>() };
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

/// Evaluate a polynomial at a given point.
public fun evaluate(p: &Polynomial, x: u8): u8 {
    let mut result = 0;
    let n = p.coefficients.length();
    n.do!(|i| {
        result = gf256::add(gf256::mul(result, x), p.coefficients[n - i - 1]);
    });
    result
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
