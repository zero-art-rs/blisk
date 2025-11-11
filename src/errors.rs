use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("compilation error: {0}")]
    CompilationError(String),

    #[error("resolution error: {0}")]
    ResolutionError(String),
}
