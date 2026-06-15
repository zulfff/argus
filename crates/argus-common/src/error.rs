use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArgusError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("eBPF error: {0}")]
    Ebpf(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("authentication error: {0}")]
    Auth(String),

    #[error("authorization error: {0}")]
    Forbidden(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("rate limited: retry after {0} seconds")]
    RateLimited(u64),

    #[error("external service error: {0}")]
    External(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ArgusError>;
