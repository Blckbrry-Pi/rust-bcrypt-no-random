#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = bcrypt_no_getrandom::hash(&data, 4);
});
