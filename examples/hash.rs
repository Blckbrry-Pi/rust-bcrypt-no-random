extern crate bcrypt_no_getrandom;

#[cfg(any(feature = "alloc", feature = "std"))]
use bcrypt_no_getrandom::{hash_with_salt, verify, Version::TwoB, DEFAULT_COST};

static SALT: [u8; 16] = *b"abcdefghijklmnop";

#[cfg(any(feature = "alloc", feature = "std"))]
fn main() {
    let hashed = hash_with_salt("hunter2", DEFAULT_COST, SALT)
        .unwrap()
        .format_for_version(TwoB);
    let valid = verify("hunter2", &hashed).unwrap();
    println!("{:?}", valid);
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
fn main() {}
