use thiserror::Error;

#[derive(Debug, Error)]
pub enum HostError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("sync transport: {0}")]
    Sync(#[from] portty_transport::error::SyncError),

    #[error("transport: {0}")]
    Transport(#[from] portty_transport::error::TransportError),

    #[error("pty: {0}")]
    Pty(String),

    #[error("relay: {0}")]
    Relay(String),

    #[error("serialization: {0}")]
    Serialization(String),

    #[error("acp: {0}")]
    Acp(String),

    #[error("limit: {0}")]
    Limit(String),
}

pub type HostResult<T> = Result<T, HostError>;
