use core::fmt;

#[cfg(feature = "std")]
use std::error;
#[cfg(feature = "std")]
use std::io;

/// Library generic result type.
pub type BcryptResult<T> = Result<T, BcryptError>;

#[derive(Debug)]
/// All the errors we can encounter while hashing/verifying
/// passwords
pub enum BcryptError {
    #[cfg(feature = "std")]
    Io(io::Error),
    CostNotAllowed(u32),
    InvalidCost,
    InvalidPrefix,
    InvalidHash(&'static str),
    InvalidSaltLen(usize),
    InvalidSalt,
    InvalidBase64(base64::DecodeSliceError),
    Other(&'static str),
}

macro_rules! impl_from_error {
    ($f: ty, $e: expr) => {
        impl From<$f> for BcryptError {
            fn from(f: $f) -> BcryptError {
                $e(f)
            }
        }
    };
}

impl_from_error!(base64::DecodeSliceError, BcryptError::InvalidBase64);
#[cfg(feature = "std")]
impl_from_error!(io::Error, BcryptError::Io);

impl fmt::Display for BcryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "std")]
            BcryptError::Io(ref err) => write!(f, "IO error: {}", err),
            BcryptError::InvalidCost => write!(f, "Invalid Cost"),
            BcryptError::CostNotAllowed(ref cost) => write!(
                f,
                "Cost needs to be between {} and {}, got {}",
                crate::MIN_COST,
                crate::MAX_COST,
                cost
            ),
            BcryptError::InvalidPrefix => write!(f, "Invalid Prefix"),
            BcryptError::InvalidHash(ref hash) => write!(f, "Invalid hash: {}", hash),
            BcryptError::InvalidBase64(ref err) => write!(f, "Base64 error: {}", err),
            BcryptError::InvalidSaltLen(len) => {
                write!(f, "Invalid salt len: expected 16, received {}", len)
            }
            BcryptError::InvalidSalt => write!(f, "Invalid salt"),
            BcryptError::Other(ref err) => write!(f, "{}", err),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for BcryptError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            BcryptError::Io(ref err) => Some(err),
            BcryptError::InvalidCost
            | BcryptError::InvalidSalt
            | BcryptError::InvalidPrefix
            | BcryptError::CostNotAllowed(_)
            | BcryptError::InvalidHash(_)
            | BcryptError::Other(_)
            | BcryptError::InvalidSaltLen(_) => None,
            BcryptError::InvalidBase64(ref err) => Some(err),
        }
    }
}
