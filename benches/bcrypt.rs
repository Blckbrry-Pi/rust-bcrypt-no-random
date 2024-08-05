#![feature(test)]
extern crate bcrypt_no_getrandom;
extern crate test;

use bcrypt_no_getrandom::{hash_with_salt, DEFAULT_COST};

static SALT: [u8; 16] = *b"hello world salt";

#[bench]
fn bench_cost_4(b: &mut test::Bencher) {
    b.iter(|| hash_with_salt("hunter2", 4, SALT));
}

#[bench]
fn bench_cost_10(b: &mut test::Bencher) {
    b.iter(|| hash_with_salt("hunter2", 10, SALT));
}

#[bench]
fn bench_cost_default(b: &mut test::Bencher) {
    b.iter(|| hash_with_salt("hunter2", DEFAULT_COST, SALT));
}

#[bench]
fn bench_cost_14(b: &mut test::Bencher) {
    b.iter(|| hash_with_salt("hunter2", 14, SALT));
}
