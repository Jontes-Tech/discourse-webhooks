# Discourse Webhooks

A type-safe Rust library for handling Discourse webhook events.

## Supported Events

- `topic_created` - When a new topic is created
- `topic_edited` - When a topic is edited
- `topic_destroyed` - When a topic is deleted
- `topic_recovered` - When a deleted topic is restored
- `post_created` - When a new post is created
- `post_edited` - When a post is edited  
- `post_destroyed` - When a post is deleted
- `post_recovered` - When a deleted post is restored
- `ping` - Webhook ping/health check events

## Usage

### Basic Event Parsing

```rust
use discourse_webhooks::{parse_webhook_payload, WebhookEventPayload};
use serde_json::json;

let payload = json!({
    "topic": {
        "id": 123,
        "title": "Hello World",
        "created_at": "2023-01-01T00:00:00Z",
        // ... other fields
    }
});

let event = parse_webhook_payload("topic_created", payload)?;

match event {
    WebhookEventPayload::TopicEvent(topic_event) => {
        println!("New topic: {}", topic_event.topic.title);
    }
    WebhookEventPayload::PostEvent(post_event) => {
        println!("New post: {}", post_event.post.raw);
    }
    WebhookEventPayload::Generic(value) => {
        println!("Unknown event: {:?}", value);
    }
}
```

### Signature Verification

```rust
use discourse_webhooks::verify_signature;

let secret = "your_webhook_secret";
let payload = r#"{"topic":{"id":123}}"#;
let signature = "sha256=abcdef1234567890...";

verify_signature(secret, payload, signature)?;
println!("Signature verified!");
```

### Event Handler Trait

```rust
use discourse_webhooks::{WebhookEventHandler, TopicWebhookEvent, PostWebhookEvent, DiscourseInstance};

struct MyHandler;

impl WebhookEventHandler for MyHandler {
    type Error = String;

    fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        println!("Topic created: {}", event.topic.title);
        // Your custom logic here
        Ok(())
    }

    fn handle_post_created(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        println!("Post created: {}", event.post.raw);
        // Your custom logic here  
        Ok(())
    }
}

// Process events
let mut handler = MyHandler;
let instance = DiscourseInstance::EthereumMagicians;
process_webhook_event(&mut handler, &instance, "topic_created", payload)?;
```

### Complete Webhook Endpoint

```rust
use discourse_webhooks::{
    DiscourseInstance, verify_json_signature, process_webhook_event,
    WebhookEventHandler, TopicWebhookEvent, PostWebhookEvent
};

struct ForumHandler {
    // Your application state
}

impl WebhookEventHandler for ForumHandler {
    type Error = String;
    
    fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        // Handle new topics
        println!("New topic: {}", event.topic.title);
        Ok(())
    }

    fn handle_post_created(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        // Handle new posts
        println!("New post in topic: {}", event.post.topic_title);
        Ok(())
    }
}

// In your webhook endpoint
fn handle_webhook(
    instance_header: &str,
    event_type: &str, 
    signature: &str,
    payload: serde_json::Value
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse instance
    let instance = DiscourseInstance::from_url(instance_header)?;
    
    if !instance.is_valid() {
        return Err("Invalid Discourse instance".into());
    }

    // Verify signature
    let secret = "your_webhook_secret";
    verify_json_signature(secret, &payload, signature)?;

    // Process event
    let mut handler = ForumHandler { /* ... */ };
    process_webhook_event(&mut handler, &instance, event_type, payload)?;

    Ok(())
}
```
