//! Easily hash and verify passwords using bcrypt
//!
//! Forked to remove getrandom dependency completely

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(any(feature = "alloc", feature = "std", test))]
extern crate alloc;

#[cfg(any(feature = "alloc", feature = "std", test))]
use alloc::string::{String, ToString};

use base64::Engine;
use base64::{alphabet::BCRYPT, engine::general_purpose::NO_PAD, engine::GeneralPurpose};
#[cfg(any(feature = "alloc", feature = "std"))]
use core::convert::AsRef;
use core::{
    fmt,
    str::{self, FromStr},
};

mod bcrypt;
mod errors;

pub use crate::bcrypt::bcrypt;
pub use crate::errors::{BcryptError, BcryptResult};

// Cost constants
const MIN_COST: u32 = 4;
const MAX_COST: u32 = 31;
pub const DEFAULT_COST: u32 = 12;
pub const BASE_64: GeneralPurpose = GeneralPurpose::new(&BCRYPT, NO_PAD);

// #[cfg(any(feature = "alloc", feature = "std"))]
#[derive(Debug, PartialEq)]
/// A bcrypt hash result before concatenating
pub struct HashParts {
    cost: u32,
    salt: [u8; 22],
    hash: [u8; 31],
}

#[derive(Clone, Debug)]
/// BCrypt hash version
/// https://en.wikipedia.org/wiki/Bcrypt#Versioning_history
pub enum Version {
    TwoA,
    TwoX,
    TwoY,
    TwoB,
}

impl Version {
    pub fn as_static_str(self) -> &'static str {
        match self {
            Version::TwoA => "2a",
            Version::TwoB => "2b",
            Version::TwoX => "2x",
            Version::TwoY => "2y",
        }
    }
}

impl HashParts {
    /// Get the bcrypt hash cost
    pub fn get_cost(&self) -> u32 {
        self.cost
    }

    /// Get the bcrypt hash salt
    pub fn get_salt(&self) -> &str {
        str::from_utf8(&self.salt).unwrap()
    }

    /// Creates the bcrypt hash string from all its part, allowing to customize the version.
    ///
    /// Expects an exactly 60-byte output buffer.
    ///
    /// *See also: [`Self::format_for_version`]*
    pub fn format_for_version_into(&self, version: Version, output: &mut [u8]) {
        output[0] = b'$';
        output[1..3].copy_from_slice(version.as_static_str().as_bytes());
        output[3] = b'$';

        output[4] = b'0' + (self.cost / 10) as u8;
        output[5] = b'0' + (self.cost % 10) as u8;

        output[6] = b'$';
        output[7..29].copy_from_slice(&self.salt);
        output[29..].copy_from_slice(&self.hash);
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    /// Creates the bcrypt hash string from all its part, allowing to customize the version.
    pub fn format_for_version(&self, version: Version) -> String {
        // Cost need to have a length of 2 so padding with a 0 if cost < 10
        alloc::format!(
            "${}${:02}${}{}",
            version,
            self.cost,
            self.get_salt(),
            str::from_utf8(&self.hash).unwrap(),
        )
    }
}

impl FromStr for HashParts {
    type Err = BcryptError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        split_hash(s)
    }
}

#[cfg(any(feature = "alloc", feature = "std"))]
impl ToString for HashParts {
    fn to_string(&self) -> String {
        self.format_for_version(Version::TwoY)
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            Version::TwoA => "2a",
            Version::TwoB => "2b",
            Version::TwoX => "2x",
            Version::TwoY => "2y",
        };
        write!(f, "{}", str)
    }
}

/// The main meat: actually does the hashing and does some verification with
/// the cost to ensure it's a correct one
fn _hash_password(password: &[u8], cost: u32, salt: [u8; 16]) -> BcryptResult<HashParts> {
    if !(MIN_COST..=MAX_COST).contains(&cost) {
        return Err(BcryptError::CostNotAllowed(cost));
    }

    let mut truncated = [0; 72];
    let capped_len = password.len().min(truncated.len());

    truncated[..capped_len].copy_from_slice(&password[..capped_len]);

    let borrowed_len = (capped_len + 1).min(truncated.len());

    let output = bcrypt::bcrypt(cost, salt, &truncated[..borrowed_len]);

    unsafe {
        // Zeroize the truncated buffer (not optimized away)
        core::ptr::write_volatile(&mut truncated, [0; 72]);
    }

    let mut salt_buf = [0; 22];
    let mut hash_buf = [0; 31];

    if BASE_64.encode_slice(salt, &mut salt_buf).is_err() {
        return Err(BcryptError::Other("Failed to encode bcrypt output"));
    }

    if BASE_64.encode_slice(&output[..23], &mut hash_buf).is_err() {
        // remember to remove the last byte
        return Err(BcryptError::Other("Failed to encode bcrypt output"));
    }

    Ok(HashParts {
        cost,
        salt: salt_buf,
        hash: hash_buf,
    })
}

/// Takes a full hash and split it into 3 parts:
/// cost, salt and hash
fn split_hash(hash: &str) -> BcryptResult<HashParts> {
    let mut parts = HashParts {
        cost: 0,
        salt: [0; 22],
        hash: [0; 31],
    };

    let hash = hash.trim_start_matches('$');

    let Some((prefix, cost_and_hash)) = hash.split_once('$') else {
        return Err(BcryptError::InvalidHash("Wrong number of parts"));
    };

    let Some((cost, hash)) = cost_and_hash.split_once('$') else {
        return Err(BcryptError::InvalidHash("Wrong number of parts"));
    };

    if hash.contains('$') {
        return Err(BcryptError::InvalidHash("Wrong number of parts"));
    }

    if prefix != "2y" && prefix != "2b" && prefix != "2a" && prefix != "2x" {
        return Err(BcryptError::InvalidPrefix);
    }

    if let Ok(c) = cost.parse::<u32>() {
        parts.cost = c;
    } else {
        return Err(BcryptError::InvalidCost);
    }

    if hash.len() == 53 && hash.is_char_boundary(22) {
        parts.salt = hash.as_bytes()[..22]
            .try_into()
            .map_err(|_| BcryptError::InvalidSalt)?;
        parts.hash = hash.as_bytes()[22..]
            .try_into()
            .map_err(|_| BcryptError::InvalidSalt)?;
    } else {
        return Err(BcryptError::InvalidHash("Wrong hash length"));
    }

    Ok(parts)
}

/// Generates a password given a hash and a cost.
/// The function returns a result structure and allows to format the hash in different versions.
pub fn hash_with_salt<P: AsRef<[u8]>>(
    password: P,
    cost: u32,
    salt: [u8; 16],
) -> BcryptResult<HashParts> {
    _hash_password(password.as_ref(), cost, salt)
}

/// Verify that a password is equivalent to the hash provided
pub fn verify<P: AsRef<[u8]>>(password: P, hash: &str) -> BcryptResult<bool> {
    use subtle::ConstantTimeEq;

    let parts = split_hash(hash)?;
    let mut salt = [0; 16];
    BASE_64.decode_slice(&parts.salt, &mut salt)?;

    let generated = _hash_password(password.as_ref(), parts.cost, salt)?;

    let mut source_decoded = [0; 23];
    let mut generated_decoded = [0; 23];
    BASE_64.decode_slice(parts.hash, &mut source_decoded)?;
    BASE_64.decode_slice(generated.hash, &mut generated_decoded)?;

    Ok(source_decoded.ct_eq(&generated_decoded).into())
}

#[cfg(all(test))]
mod tests {
    use super::{
        _hash_password,
        alloc::{
            string::{String, ToString},
            vec,
        },
        hash_with_salt, split_hash, verify, BcryptError, HashParts, Version, DEFAULT_COST,
    };
    use core::convert::TryInto;
    use core::iter;
    use core::str::FromStr;

    #[test]
    fn can_split_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let output = split_hash(hash).unwrap();
        let expected = HashParts {
            cost: 12,
            salt: "L6Bc/AlTQHyd9liGgGEZyO".as_bytes().try_into().unwrap(),
            hash: "FLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u"
                .as_bytes()
                .try_into()
                .unwrap(),
        };
        assert_eq!(output, expected);
    }

    #[test]
    fn can_output_cost_and_salt_from_parsed_hash() {
        let hash = "$2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        let parsed = HashParts::from_str(hash).unwrap();
        assert_eq!(parsed.get_cost(), 12);
        assert_eq!(parsed.get_salt(), "L6Bc/AlTQHyd9liGgGEZyO".to_string());
    }

    #[test]
    fn returns_an_error_if_a_parsed_hash_is_baddly_formated() {
        let hash1 = "$2y$12$L6Bc/AlTQHyd9lGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash1).is_err());

        let hash2 = "!2y$12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash2).is_err());

        let hash3 = "$2y$-12$L6Bc/AlTQHyd9liGgGEZyOFLPHNgyxeEPfgYfBCVxJ7JIlwxyVU3u";
        assert!(HashParts::from_str(hash3).is_err());
    }

    #[test]
    fn can_verify_hash_generated_from_some_online_tool() {
        let hash = "$2a$04$UuTkLRZZ6QofpDOlMz32MuuxEHA43WOemOYHPz6.SjsVsyO1tDU96";
        assert!(verify("password", hash).unwrap());
    }

    #[test]
    fn can_verify_hash_generated_from_python() {
        let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        assert!(verify("correctbatteryhorsestapler", hash).unwrap());
    }

    #[test]
    fn can_verify_hash_generated_from_node() {
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).unwrap());
    }

    #[test]
    fn can_verify_hash_generated_from_go() {
        /*
            package main
            import (
                "io"
                "os"
                "golang.org/x/crypto/bcrypt"
            )
            func main() {
                buf, err := io.ReadAll(os.Stdin)
                if err != nil {
                    panic(err)
                }
                out, err := bcrypt.GenerateFromPassword(buf, bcrypt.MinCost)
                if err != nil {
                    panic(err)
                }
                os.Stdout.Write(out)
                os.Stdout.Write([]byte("\n"))
            }
        */
        let binary_input = vec![
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash = "$2a$04$tjARW6ZON3PhrAIRW2LG/u9aDw5eFdstYLR8nFCNaOQmsH9XD23w.";
        assert!(verify(binary_input, hash).unwrap());
    }

    #[test]
    fn invalid_hash_does_not_panic() {
        let binary_input = vec![
            29, 225, 195, 167, 223, 236, 85, 195, 114, 227, 7, 0, 209, 239, 189, 24, 51, 105, 124,
            168, 151, 75, 144, 64, 198, 197, 196, 4, 241, 97, 110, 135,
        ];
        let hash = "$2a$04$tjARW6ZON3PhrAIRW2LG/u9a.";
        assert!(verify(binary_input, hash).is_err());
    }

    #[test]
    fn a_wrong_password_is_false() {
        let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        assert!(!verify("wrong", hash).unwrap());
    }

    #[test]
    fn errors_with_invalid_hash() {
        // there is another $ in the hash part
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
    }

    #[test]
    fn errors_with_non_number_cost() {
        // the cost is not a number
        let hash = "$2a$ab$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIi";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
    }

    #[test]
    fn errors_with_a_hash_too_long() {
        // the cost is not a number
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk$5bektyVVa5xnIerererereri";
        assert!(verify("correctbatteryhorsestapler", hash).is_err());
    }

    #[test]
    fn long_passwords_truncate_correctly() {
        // produced with python -c 'import bcrypt; bcrypt.hashpw(b"x"*100, b"$2a$05$...............................")'
        let hash = "$2a$05$......................YgIDy4hFBdVlc/6LHnD9mX488r9cLd2";
        assert!(verify(iter::repeat("x").take(100).collect::<String>(), hash).unwrap());
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn generate_versions() {
        let password = "hunter2".as_bytes();
        let salt = vec![0; 16];
        let result = _hash_password(password, DEFAULT_COST, salt.try_into().unwrap()).unwrap();
        assert_eq!(
            "$2a$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoA)
        );
        assert_eq!(
            "$2b$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoB)
        );
        assert_eq!(
            "$2x$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoX)
        );
        assert_eq!(
            "$2y$12$......................21jzCB1r6pN6rp5O2Ev0ejjTAboskKm",
            result.format_for_version(Version::TwoY)
        );
        let hash = result.to_string();
        assert_eq!(true, verify("hunter2", &hash).unwrap());
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn allow_null_bytes() {
        // hash p1, check the hash against p2:
        fn hash_and_check(p1: &[u8], p2: &[u8]) -> Result<bool, BcryptError> {
            let fast_cost = 4;
            match hash_with_salt(p1, fast_cost, [0x11; 16]) {
                Ok(s) => verify(p2, &s.format_for_version(Version::TwoB)),
                Err(e) => Err(e),
            }
        }
        fn assert_valid_password(p1: &[u8], p2: &[u8], expected: bool) {
            match hash_and_check(p1, p2) {
                Ok(checked) => {
                    if checked != expected {
                        panic!(
                            "checked {:?} against {:?}, incorrect result {}",
                            p1, p2, checked
                        )
                    }
                }
                Err(e) => panic!("error evaluating password: {} for {:?}.", e, p1),
            }
        }

        // bcrypt should consider all of these distinct:
        let test_passwords = vec![
            "\0",
            "passw0rd\0",
            "password\0with tail",
            "\0passw0rd",
            "a",
            "a\0",
            "a\0b\0",
        ];

        for (i, p1) in test_passwords.iter().enumerate() {
            for (j, p2) in test_passwords.iter().enumerate() {
                assert_valid_password(p1.as_bytes(), p2.as_bytes(), i == j);
            }
        }

        // this is a quirk of the bcrypt algorithm: passwords that are entirely null
        // bytes hash to the same value, even if they are different lengths:
        assert_valid_password("\0\0\0\0\0\0\0\0".as_bytes(), "\0".as_bytes(), true);
    }

    #[cfg(any(feature = "alloc", feature = "std"))]
    #[test]
    fn hash_with_fixed_salt() {
        let salt = [
            38, 113, 212, 141, 108, 213, 195, 166, 201, 38, 20, 13, 47, 40, 104, 18,
        ];
        let hashed = hash_with_salt("My S3cre7 P@55w0rd!", 5, salt)
            .unwrap()
            .to_string();
        assert_eq!(
            "$2y$05$HlFShUxTu4ZHHfOLJwfmCeDj/kuKFKboanXtDJXxCC7aIPTUgxNDe",
            &hashed
        );
    }

    #[test]
    fn does_no_error_on_char_boundary_splitting() {
        // Just checks that it does not panic
        let _ = verify(
            &[],
            "2a$$$0$OOOOOOOOOOOOOOOOOOOOO£OOOOOOOOOOOOOOOOOOOOOOOOOOOOOO",
        );
    }
}
