//! # Discourse Webhooks
//!
//! A type-safe Rust library for handling Discourse webhook events.
//!
//! This crate provides:
//! - Type-safe event parsing for Discourse webhooks
//! - HMAC-SHA256 signature verification
//! - Trait-based event handling system with async support
//! - Support for all major Discourse webhook events
//!
//! ## Quick Start
//!
//! ```rust
//! use discourse_webhooks::{WebhookEventHandler, WebhookProcessor, TopicWebhookEvent};
//! use async_trait::async_trait;
//!
//! struct MyHandler;
//!
//! #[async_trait]
//! impl WebhookEventHandler for MyHandler {
//!     type Error = String;
//!
//!     async fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
//!         println!("New topic: {}", event.topic.title);
//!         Ok(())
//!     }
//! }
//!
//! // Process webhook events
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let processor = WebhookProcessor::new();
//! let mut handler = MyHandler;
//! // processor.process_json(&mut handler, "topic_created", payload, None).await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod events;
pub mod signature;

#[cfg(feature = "async")]
pub use async_trait::async_trait;
pub use error::{Result, WebhookError};
pub use events::{
    parse_webhook_payload, PostWebhookEvent, TopicWebhookEvent, WebhookEventPayload, WebhookPost,
    WebhookTopic, WebhookUser,
};
pub use signature::{verify_json_signature, verify_signature, SignatureVerificationError};

use serde::{Deserialize, Serialize};

/// Represents a Discourse webhook payload structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscourseWebhookPayload {
    /// The event type (e.g., "topic_created", "post_edited")
    #[serde(default)]
    pub event: Option<String>,
    /// The webhook data payload
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    /// Unix timestamp when the event occurred
    #[serde(default)]
    pub timestamp: Option<i64>,
}

/// Trait for handling different types of webhook events
///
/// Implement this trait to define custom behavior for each event type.
/// All methods have default implementations that do nothing, so you only
/// need to implement the events you care about.
///
/// # Examples (Sync)
/// ```rust
/// use discourse_webhooks::{WebhookEventHandler, TopicWebhookEvent};
///
/// struct MyHandler;
///
/// impl WebhookEventHandler for MyHandler {
///     type Error = String;
///
///     fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
///         println!("Topic created: {}", event.topic.title);
///         Ok(())
///     }
/// }
/// ```
///
/// # Examples (Async - requires "async" feature)
/// ```rust
/// # #[cfg(feature = "async")]
/// # {
/// use discourse_webhooks::{WebhookEventHandler, TopicWebhookEvent, async_trait};
///
/// struct MyHandler;
///
/// #[async_trait]
/// impl WebhookEventHandler for MyHandler {
///     type Error = String;
///
///     async fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
///         // Your async logic here
///         println!("Topic created: {}", event.topic.title);
///         Ok(())
///     }
/// }
/// # }
/// ```
#[cfg(not(feature = "async"))]
pub trait WebhookEventHandler {
    /// The error type returned by event handlers
    type Error;

    /// Called when a new topic is created
    fn handle_topic_created(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a topic is edited
    fn handle_topic_edited(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a topic is deleted/destroyed
    fn handle_topic_destroyed(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a deleted topic is recovered
    fn handle_topic_recovered(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a new post is created
    fn handle_post_created(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a post is edited
    fn handle_post_edited(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a post is deleted/destroyed
    fn handle_post_destroyed(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a deleted post is recovered
    fn handle_post_recovered(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a ping event is received
    fn handle_ping(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(feature = "async")]
#[async_trait]
pub trait WebhookEventHandler {
    /// The error type returned by event handlers
    type Error;

    /// Called when a new topic is created
    async fn handle_topic_created(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a topic is edited
    async fn handle_topic_edited(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a topic is deleted/destroyed
    async fn handle_topic_destroyed(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a deleted topic is recovered
    async fn handle_topic_recovered(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a new post is created
    async fn handle_post_created(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a post is edited
    async fn handle_post_edited(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a post is deleted/destroyed
    async fn handle_post_destroyed(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a deleted post is recovered
    async fn handle_post_recovered(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    /// Called when a ping event is received
    async fn handle_ping(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

/// Process a webhook event using the provided handler (synchronous version)
///
/// This function parses the payload based on the event type and calls
/// the appropriate handler method.
///
/// # Arguments
/// * `handler` - Mutable reference to an event handler
/// * `event_type` - The type of event (e.g., "topic_created")
/// * `payload` - The JSON payload from the webhook
///
/// # Returns
/// * `Ok(())` if the event was processed successfully
/// * `Err(WebhookError)` if parsing or handling failed
#[cfg(not(feature = "async"))]
pub fn process_webhook_event<H: WebhookEventHandler>(
    handler: &mut H,
    event_type: &str,
    payload: serde_json::Value,
) -> std::result::Result<(), WebhookError<H::Error>> {
    match event_type {
        "topic_created" | "topic_edited" | "topic_destroyed" | "topic_recovered" => {
            let event = parse_webhook_payload(event_type, payload)?;
            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                let result = match event_type {
                    "topic_created" => handler.handle_topic_created(&topic_event),
                    "topic_edited" => handler.handle_topic_edited(&topic_event),
                    "topic_destroyed" => handler.handle_topic_destroyed(&topic_event),
                    "topic_recovered" => handler.handle_topic_recovered(&topic_event),
                    _ => unreachable!(),
                };
                result.map_err(WebhookError::HandlerError)?;
            }
        }
        "post_created" | "post_edited" | "post_destroyed" | "post_recovered" => {
            let event = parse_webhook_payload(event_type, payload)?;
            if let WebhookEventPayload::PostEvent(post_event) = event {
                let result = match event_type {
                    "post_created" => handler.handle_post_created(&post_event),
                    "post_edited" => handler.handle_post_edited(&post_event),
                    "post_destroyed" => handler.handle_post_destroyed(&post_event),
                    "post_recovered" => handler.handle_post_recovered(&post_event),
                    _ => unreachable!(),
                };
                result.map_err(WebhookError::HandlerError)?;
            }
        }
        "ping" => {
            handler.handle_ping().map_err(WebhookError::HandlerError)?;
        }
        _ => {
            return Err(WebhookError::UnknownEventType(event_type.to_string()));
        }
    }

    Ok(())
}

/// Process a webhook event using the provided handler (asynchronous version)
///
/// This function parses the payload based on the event type and calls
/// the appropriate handler method.
///
/// # Arguments
/// * `handler` - Mutable reference to an event handler
/// * `event_type` - The type of event (e.g., "topic_created")
/// * `payload` - The JSON payload from the webhook
///
/// # Returns
/// * `Ok(())` if the event was processed successfully
/// * `Err(WebhookError)` if parsing or handling failed
#[cfg(feature = "async")]
pub async fn process_webhook_event<H: WebhookEventHandler + Send>(
    handler: &mut H,
    event_type: &str,
    payload: serde_json::Value,
) -> std::result::Result<(), WebhookError<H::Error>> {
    match event_type {
        "topic_created" | "topic_edited" | "topic_destroyed" | "topic_recovered" => {
            let event = parse_webhook_payload(event_type, payload)?;
            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                let result = match event_type {
                    "topic_created" => handler.handle_topic_created(&topic_event).await,
                    "topic_edited" => handler.handle_topic_edited(&topic_event).await,
                    "topic_destroyed" => handler.handle_topic_destroyed(&topic_event).await,
                    "topic_recovered" => handler.handle_topic_recovered(&topic_event).await,
                    _ => unreachable!(),
                };
                result.map_err(WebhookError::HandlerError)?;
            }
        }
        "post_created" | "post_edited" | "post_destroyed" | "post_recovered" => {
            let event = parse_webhook_payload(event_type, payload)?;
            if let WebhookEventPayload::PostEvent(post_event) = event {
                let result = match event_type {
                    "post_created" => handler.handle_post_created(&post_event).await,
                    "post_edited" => handler.handle_post_edited(&post_event).await,
                    "post_destroyed" => handler.handle_post_destroyed(&post_event).await,
                    "post_recovered" => handler.handle_post_recovered(&post_event).await,
                    _ => unreachable!(),
                };
                result.map_err(WebhookError::HandlerError)?;
            }
        }
        "ping" => {
            handler
                .handle_ping()
                .await
                .map_err(WebhookError::HandlerError)?;
        }
        _ => {
            return Err(WebhookError::UnknownEventType(event_type.to_string()));
        }
    }

    Ok(())
}

/// A webhook processor that handles signature verification and event dispatching
///
/// This struct provides a convenient way to process webhook events with
/// optional signature verification.
///
/// # Examples
///
/// ```rust
/// use discourse_webhooks::WebhookProcessor;
///
/// // Without signature verification
/// let processor = WebhookProcessor::new();
///
/// // With signature verification
/// let processor = WebhookProcessor::new()
///     .with_secret("your_webhook_secret");
/// ```
#[derive(Debug, Clone)]
pub struct WebhookProcessor {
    secret: Option<String>,
    verify_signatures: bool,
}

impl WebhookProcessor {
    /// Create a new webhook processor with default settings
    ///
    /// By default, signature verification is disabled.
    pub fn new() -> Self {
        Self {
            secret: None,
            verify_signatures: false,
        }
    }

    /// Enable signature verification with the provided secret
    ///
    /// # Arguments
    /// * `secret` - The shared secret key for HMAC verification
    pub fn with_secret<S: Into<String>>(mut self, secret: S) -> Self {
        self.secret = Some(secret.into());
        self.verify_signatures = true;
        self
    }

    /// Disable signature verification
    ///
    /// This can be useful for development or when webhooks are received
    /// through a trusted channel.
    pub fn without_signature_verification(mut self) -> Self {
        self.verify_signatures = false;
        self
    }

    /// Check if signature verification is enabled
    pub fn verifies_signatures(&self) -> bool {
        self.verify_signatures
    }

    /// Get the configured secret (if any)
    pub fn secret(&self) -> Option<&str> {
        self.secret.as_deref()
    }

    /// Process a webhook from a string payload
    ///
    /// # Arguments
    /// * `handler` - Mutable reference to an event handler
    /// * `event_type` - The type of event (e.g., "topic_created")
    /// * `payload` - The raw JSON payload as a string
    /// * `signature` - Optional signature header for verification
    #[cfg(not(feature = "async"))]
    pub fn process<H: WebhookEventHandler>(
        &self,
        handler: &mut H,
        event_type: &str,
        payload: &str,
        signature: Option<&str>,
    ) -> Result<(), H::Error> {
        if self.verify_signatures {
            if let Some(secret) = &self.secret {
                if let Some(sig) = signature {
                    signature::verify_signature(secret, payload, sig)
                        .map_err(|_| WebhookError::InvalidSignature)?;
                } else {
                    return Err(WebhookError::InvalidSignature);
                }
            }
        }

        let json_payload: serde_json::Value = serde_json::from_str(payload)?;
        process_webhook_event(handler, event_type, json_payload)
    }

    /// Process a webhook from a string payload (async)
    ///
    /// # Arguments
    /// * `handler` - Mutable reference to an event handler
    /// * `event_type` - The type of event (e.g., "topic_created")
    /// * `payload` - The raw JSON payload as a string
    /// * `signature` - Optional signature header for verification
    #[cfg(feature = "async")]
    pub async fn process<H: WebhookEventHandler + Send>(
        &self,
        handler: &mut H,
        event_type: &str,
        payload: &str,
        signature: Option<&str>,
    ) -> Result<(), H::Error> {
        if self.verify_signatures {
            if let Some(secret) = &self.secret {
                if let Some(sig) = signature {
                    signature::verify_signature(secret, payload, sig)
                        .map_err(|_| WebhookError::InvalidSignature)?;
                } else {
                    return Err(WebhookError::InvalidSignature);
                }
            }
        }

        let json_payload: serde_json::Value = serde_json::from_str(payload)?;
        process_webhook_event(handler, event_type, json_payload).await
    }

    /// Process a webhook from a JSON value
    ///
    /// # Arguments
    /// * `handler` - Mutable reference to an event handler
    /// * `event_type` - The type of event (e.g., "topic_created")
    /// * `payload` - The JSON payload as a serde_json::Value
    /// * `signature` - Optional signature header for verification
    #[cfg(not(feature = "async"))]
    pub fn process_json<H: WebhookEventHandler>(
        &self,
        handler: &mut H,
        event_type: &str,
        payload: serde_json::Value,
        signature: Option<&str>,
    ) -> Result<(), H::Error> {
        if self.verify_signatures {
            if let Some(secret) = &self.secret {
                if let Some(sig) = signature {
                    signature::verify_json_signature(secret, &payload, sig)
                        .map_err(|_| WebhookError::InvalidSignature)?;
                } else {
                    return Err(WebhookError::InvalidSignature);
                }
            }
        }

        process_webhook_event(handler, event_type, payload)
    }

    /// Process a webhook from a JSON value (async)
    ///
    /// # Arguments
    /// * `handler` - Mutable reference to an event handler
    /// * `event_type` - The type of event (e.g., "topic_created")
    /// * `payload` - The JSON payload as a serde_json::Value
    /// * `signature` - Optional signature header for verification
    #[cfg(feature = "async")]
    pub async fn process_json<H: WebhookEventHandler + Send>(
        &self,
        handler: &mut H,
        event_type: &str,
        payload: serde_json::Value,
        signature: Option<&str>,
    ) -> Result<(), H::Error> {
        if self.verify_signatures {
            if let Some(secret) = &self.secret {
                if let Some(sig) = signature {
                    signature::verify_json_signature(secret, &payload, sig)
                        .map_err(|_| WebhookError::InvalidSignature)?;
                } else {
                    return Err(WebhookError::InvalidSignature);
                }
            }
        }

        process_webhook_event(handler, event_type, payload).await
    }
}

impl Default for WebhookProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;
    use serde_json::json;

    struct TestHandler {
        pub topic_created_count: usize,
        pub post_created_count: usize,
        pub ping_count: usize,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                topic_created_count: 0,
                post_created_count: 0,
                ping_count: 0,
            }
        }
    }

    // Sync tests
    #[cfg(not(feature = "async"))]
    impl WebhookEventHandler for TestHandler {
        type Error = String;

        fn handle_topic_created(
            &mut self,
            _event: &TopicWebhookEvent,
        ) -> std::result::Result<(), Self::Error> {
            self.topic_created_count += 1;
            Ok(())
        }

        fn handle_post_created(
            &mut self,
            _event: &PostWebhookEvent,
        ) -> std::result::Result<(), Self::Error> {
            self.post_created_count += 1;
            Ok(())
        }

        fn handle_ping(&mut self) -> std::result::Result<(), Self::Error> {
            self.ping_count += 1;
            Ok(())
        }
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_webhook_handler_ping() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "ping", json!({}));
        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_webhook_handler_invalid_event_type() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "hatasj", json!({}));
        assert!(result.is_err());

        if let Err(WebhookError::UnknownEventType(event)) = result {
            assert_eq!(event, "hatasj");
        } else {
            panic!("Expected UnknownEventType error");
        }
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_webhook_processor() {
        let processor = WebhookProcessor::new();
        let mut handler = TestHandler::new();

        let result = processor.process_json(&mut handler, "ping", json!({}), None);

        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_webhook_processor_with_signature() {
        let secret = "test_secret";
        let processor = WebhookProcessor::new().with_secret(secret);
        let mut handler = TestHandler::new();

        let payload = json!({});
        let payload_str = serde_json::to_string(&payload).unwrap();

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_str.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        let result = processor.process_json(&mut handler, "ping", payload, Some(&signature));

        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(not(feature = "async"))]
    #[test]
    fn test_unknown_event_type() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "unknown_event", json!({}));
        assert!(result.is_err());

        if let Err(WebhookError::UnknownEventType(event)) = result {
            assert_eq!(event, "unknown_event");
        } else {
            panic!("Expected UnknownEventType error");
        }
    }

    // Async tests
    #[cfg(feature = "async")]
    #[async_trait]
    impl WebhookEventHandler for TestHandler {
        type Error = String;

        async fn handle_topic_created(
            &mut self,
            _event: &TopicWebhookEvent,
        ) -> std::result::Result<(), Self::Error> {
            self.topic_created_count += 1;
            Ok(())
        }

        async fn handle_post_created(
            &mut self,
            _event: &PostWebhookEvent,
        ) -> std::result::Result<(), Self::Error> {
            self.post_created_count += 1;
            Ok(())
        }

        async fn handle_ping(&mut self) -> std::result::Result<(), Self::Error> {
            self.ping_count += 1;
            Ok(())
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_webhook_handler_ping() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "ping", json!({})).await;
        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_webhook_handler_invalid_event_type() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "hatasj", json!({})).await;
        assert!(result.is_err());

        if let Err(WebhookError::UnknownEventType(event)) = result {
            assert_eq!(event, "hatasj");
        } else {
            panic!("Expected UnknownEventType error");
        }
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_webhook_processor() {
        let processor = WebhookProcessor::new();
        let mut handler = TestHandler::new();

        let result = processor
            .process_json(&mut handler, "ping", json!({}), None)
            .await;

        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_webhook_processor_with_signature() {
        let secret = "test_secret";
        let processor = WebhookProcessor::new().with_secret(secret);
        let mut handler = TestHandler::new();

        let payload = json!({});
        let payload_str = serde_json::to_string(&payload).unwrap();

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload_str.as_bytes());
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        let result = processor
            .process_json(&mut handler, "ping", payload, Some(&signature))
            .await;

        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn test_unknown_event_type() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "unknown_event", json!({})).await;
        assert!(result.is_err());

        if let Err(WebhookError::UnknownEventType(event)) = result {
            assert_eq!(event, "unknown_event");
        } else {
            panic!("Expected UnknownEventType error");
        }
    }
}
