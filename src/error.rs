//! Error types for the discourse-webhooks crate
//!
//! This module defines all error types that can occur when processing
//! Discourse webhook events.

use serde_json;
use thiserror::Error;

/// Errors that can occur when processing webhook events
///
/// The generic parameter `H` represents the error type from the event handler.
#[derive(Error, Debug)]
pub enum WebhookError<H> {
    /// Failed to parse the webhook payload as JSON
    #[error("Failed to parse webhook payload: {0}")]
    ParseError(#[from] serde_json::Error),

    /// Error occurred in the event handler
    #[error("Handler error: {0}")]
    HandlerError(H),

    /// Webhook signature verification failed
    #[error("Invalid webhook signature")]
    InvalidSignature,

    /// Invalid Discourse instance specified
    #[error("Invalid Discourse instance: {0}")]
    InvalidInstance(String),

    /// General processing error
    #[error("Webhook processing error: {0}")]
    ProcessingError(String),

    /// Unknown or unsupported event type
    #[error("Unknown event type: {0}")]
    UnknownEventType(String),
}

/// Convenience Result type for webhook operations
///
/// Uses `Box<dyn std::error::Error + Send + Sync>` as the default handler error type.
pub type Result<T, H = Box<dyn std::error::Error + Send + Sync>> =
    std::result::Result<T, WebhookError<H>>;
