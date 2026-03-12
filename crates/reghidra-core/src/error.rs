use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("failed to read file: {0}")]
    Io(#[from] std::io::Error),

    #[error("unsupported binary format")]
    UnsupportedFormat,

    #[error("unsupported architecture: {0}")]
    UnsupportedArch(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("disassembly error: {0}")]
    Disassembly(String),

    #[error("signature file error: {0}")]
    Signature(String),

    #[error("{0}")]
    Other(String),
}
