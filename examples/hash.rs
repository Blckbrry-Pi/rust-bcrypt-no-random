extern crate bcrypt;

#[cfg(any(feature = "alloc", feature = "std"))]
use bcrypt::{hash_with_salt, verify, DEFAULT_COST};

static SALT: [u8; 16] = *b"abcdefghijklmnop";

#[cfg(any(feature = "alloc", feature = "std"))]
fn main() {
    let hashed = hash_with_salt("hunter2", DEFAULT_COST, SALT)
        .unwrap()
        .format_for_version(bcrypt::Version::TwoB);
    let valid = verify("hunter2", &hashed).unwrap();
    println!("{:?}", valid);
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
fn main() {}
