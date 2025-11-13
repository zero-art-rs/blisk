use thiserror::Error;

/// Errors related to MuSig2 protocol
#[derive(Error, Debug)]
pub enum MuSig2Error {
    #[error("signer not in cosigners list")]
    SignerNotInCosigners,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("invalid partial signature")]
    InvalidPartialSignature,

    #[error("missing nonce(s) from signer(s): {0:?}")]
    MissingNonces(Vec<String>),

    #[error("missing partial signature(s) from signer(s): {0:?}")]
    MissingPartialSignatures(Vec<String>),

    #[error("invalid aggregated signature")]
    InvalidAggregatedSignature,

    #[error("invalid message")]
    InvalidMessage,

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("invalid session state: {0}")]
    InvalidSessionState(String),

    #[error("hash function error: {0}")]
    HashFunctionError(String),
}

impl From<ark_serialize::SerializationError> for MuSig2Error {
    fn from(error: ark_serialize::SerializationError) -> Self {
        MuSig2Error::SerializationError(error.to_string())
    }
}
