//! Generic message-channel trait.
//!
//! Forked from Corvux `sync/transport/mod.rs` and genericized over the message
//! type - Corvux's was hard-coupled to its sync `Message`. Portty instantiates
//! this as `Transport<portty_protocol::Frame>`. The iroh implementation is
//! provided by `IrohTransport` in the `iroh` module.

use async_trait::async_trait;

use crate::error::TransportError;

/// One end of a bidirectional, framed, encrypted message channel carrying
/// whole messages of type `M`.
#[async_trait]
pub trait Transport<M>: Send + Sync
where
    M: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
{
    async fn send(&mut self, msg: &M) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Result<M, TransportError>;

    /// Close the underlying channel. Idempotent; subsequent ops return `Closed`.
    async fn close(&mut self) -> Result<(), TransportError>;
}
