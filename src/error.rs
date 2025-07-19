use serde_json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebhookError<H> {
    #[error("Failed to parse webhook payload: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("Handler error: {0}")]
    HandlerError(H),

    #[error("Invalid webhook signature")]
    InvalidSignature,

    #[error("Invalid Discourse instance: {0}")]
    InvalidInstance(String),

    #[error("Webhook processing error: {0}")]
    ProcessingError(String),

    #[error("Unknown event type: {0}")]
    UnknownEventType(String),
}

pub type Result<T, H = Box<dyn std::error::Error + Send + Sync>> =
    std::result::Result<T, WebhookError<H>>;
