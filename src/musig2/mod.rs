pub mod error;
pub mod protocol;
pub mod tests;
pub mod types;

pub use error::MuSig2Error;
pub use protocol::{
    DefaultMuSig2Hash, aggregate_partial_signatures, aggregate_public_keys,
    aggregate_public_keys_with_coeffs, verify_signature,
};
pub use types::{MuSig2HashFunction, MuSig2Session, MuSig2SessionState, MuSig2Signature, SignerId};
