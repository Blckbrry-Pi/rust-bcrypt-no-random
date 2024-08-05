#![no_main]
use libfuzzer_sys::fuzz_target;

static SALT: [u8; 16] = *b"hello world salt";

fuzz_target!(|data: &str| {
    let _ = bcrypt_no_getrandom::hash_with_salt(&data, 4, SALT);
});
