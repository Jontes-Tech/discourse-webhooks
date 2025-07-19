pub mod error;
pub mod events;
pub mod signature;

pub use error::{Result, WebhookError};
pub use events::{
    parse_webhook_payload, PostWebhookEvent, TopicWebhookEvent, WebhookEventPayload, WebhookPost,
    WebhookTopic, WebhookUser,
};
pub use signature::{verify_json_signature, verify_signature, SignatureVerificationError};

use serde::{Deserialize, Serialize};

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

pub trait WebhookEventHandler {
    type Error;

    fn handle_topic_created(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_topic_edited(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_topic_destroyed(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_topic_recovered(
        &mut self,
        event: &TopicWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_post_created(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_post_edited(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_post_destroyed(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_post_recovered(
        &mut self,
        event: &PostWebhookEvent,
    ) -> std::result::Result<(), Self::Error> {
        let _ = event;
        Ok(())
    }

    fn handle_ping(&mut self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

pub fn process_webhook_event<H: WebhookEventHandler>(
    handler: &mut H,
    event_type: &str,
    payload: serde_json::Value,
) -> std::result::Result<(), WebhookError<H::Error>> {
    match event_type {
        "topic_created" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                handler
                    .handle_topic_created(&topic_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "topic_edited" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                handler
                    .handle_topic_edited(&topic_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "topic_destroyed" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                handler
                    .handle_topic_destroyed(&topic_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "topic_recovered" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::TopicEvent(topic_event) = event {
                handler
                    .handle_topic_recovered(&topic_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "post_created" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::PostEvent(post_event) = event {
                handler
                    .handle_post_created(&post_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "post_edited" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::PostEvent(post_event) = event {
                handler
                    .handle_post_edited(&post_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "post_destroyed" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::PostEvent(post_event) = event {
                handler
                    .handle_post_destroyed(&post_event)
                    .map_err(WebhookError::HandlerError)?;
            }
        }
        "post_recovered" => {
            let event =
                parse_webhook_payload(event_type, payload).map_err(WebhookError::ParseError)?;

            if let WebhookEventPayload::PostEvent(post_event) = event {
                handler
                    .handle_post_recovered(&post_event)
                    .map_err(WebhookError::HandlerError)?;
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

#[derive(Debug, Clone)]
pub struct WebhookProcessor {
    secret: Option<String>,
    verify_signatures: bool,
}

impl WebhookProcessor {
    pub fn new() -> Self {
        Self {
            secret: None,
            verify_signatures: false,
        }
    }

    pub fn with_secret<S: Into<String>>(mut self, secret: S) -> Self {
        self.secret = Some(secret.into());
        self.verify_signatures = true;
        self
    }

    pub fn without_signature_verification(mut self) -> Self {
        self.verify_signatures = false;
        self
    }

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

    #[test]
    fn test_webhook_handler_ping() {
        let mut handler = TestHandler::new();
        let result = process_webhook_event(&mut handler, "ping", json!({}));
        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

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

    #[test]
    fn test_webhook_processor() {
        let processor = WebhookProcessor::new();
        let mut handler = TestHandler::new();

        let result = processor.process_json(&mut handler, "ping", json!({}), None);

        assert!(result.is_ok());
        assert_eq!(handler.ping_count, 1);
    }

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
}
