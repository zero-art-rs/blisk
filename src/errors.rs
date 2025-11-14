use thiserror::Error;

use crate::musig2::MuSig2Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("compilation error: {0}")]
    CompilationError(String),

    #[error("resolution error: {0}")]
    ResolutionError(String),

    #[error("Policies not in CNF form are not supported")]
    NotCNF,

    #[error("Missing clause public key")]
    MissingClausePublicKey,

    #[error("Invalid gate")]
    InvalidGate,

    #[error("MuSig2 error: {0}")]
    MuSig2Error(#[from] MuSig2Error),
}
