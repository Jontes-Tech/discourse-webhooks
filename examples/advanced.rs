use discourse_webhooks::{
    PostWebhookEvent, TopicWebhookEvent, WebhookError, WebhookEventHandler, WebhookProcessor,
};

struct LoggingHandler;

impl WebhookEventHandler for LoggingHandler {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        println!("📝 Topic Created:");
        println!("   Title: {}", event.topic.title);
        println!("   Author: {}", event.topic.created_by.username);
        println!("   Category ID: {}", event.topic.category_id);
        println!("   Slug: {}", event.topic.slug);
        println!();
        Ok(())
    }

    fn handle_topic_edited(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        println!("✏️  Topic Edited:");
        println!("   Title: {}", event.topic.title);
        println!("   Slug: {}", event.topic.slug);
        println!();
        Ok(())
    }

    fn handle_topic_destroyed(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        println!("🗑️  Topic Destroyed:");
        println!("   Title: {}", event.topic.title);
        if let Some(deleted_by) = &event.topic.deleted_by {
            println!("   Deleted by: {}", deleted_by.username);
        }
        println!();
        Ok(())
    }

    fn handle_post_created(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        println!("💬 Post Created:");
        println!("   Author: {}", event.post.username);
        println!("   Topic: {}", event.post.topic_title);
        println!("   Content: {}", event.post.raw);
        println!();
        Ok(())
    }

    fn handle_post_edited(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        println!("📝 Post Edited:");
        println!("   Author: {}", event.post.username);
        println!("   Topic: {}", event.post.topic_title);
        println!("   Updated content: {}", event.post.raw);
        println!();
        Ok(())
    }

    fn handle_ping(&mut self) -> Result<(), Self::Error> {
        println!("🏓 Received ping from Discourse");
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Discourse Webhook Handler Example\n");

    let webhook_secret = "my_webhook_secret";
    let processor = WebhookProcessor::new().with_secret(webhook_secret);
    let mut handler = LoggingHandler;

    let payload_str = r#"{
        "post": {
            "admin": true,
            "avatar_template": "/user_avatar/og.ax/jonte/{size}/3_2.png",
            "bookmarked": false,
            "category_id": 4,
            "category_slug": "general",
            "cooked": "<p>Hello World! This is an example post.</p>",
            "created_at": "2025-07-19T12:09:30.847Z",
            "deleted_at": null,
            "display_username": null,
            "edit_reason": null,
            "flair_group_id": null,
            "flair_name": null,
            "hidden": false,
            "id": 14,
            "incoming_link_count": 0,
            "moderator": false,
            "name": null,
            "post_number": 1,
            "post_type": 1,
            "post_url": "/t/example-topic/10/1",
            "posts_count": 1,
            "primary_group_name": null,
            "quote_count": 0,
            "raw": "Hello World! This is an example post.",
            "reads": 0,
            "reply_count": 0,
            "reply_to_post_number": null,
            "reviewable_id": null,
            "reviewable_score_count": 0,
            "reviewable_score_pending_count": 0,
            "score": 0.0,
            "staff": true,
            "topic_archetype": "regular",
            "topic_filtered_posts_count": 1,
            "topic_id": 10,
            "topic_posts_count": 1,
            "topic_slug": "example-topic",
            "topic_title": "Example Topic",
            "trust_level": 1,
            "updated_at": "2025-07-19T12:09:30.847Z",
            "user_deleted": false,
            "user_id": 2,
            "user_title": null,
            "username": "example_user",
            "version": 1,
            "wiki": false
        }
    }"#;

    let signature = {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())?;
        mac.update(payload_str.as_bytes());
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    };

    println!("Processing webhook with signature verification...");
    match processor.process(&mut handler, "post_created", &payload_str, Some(&signature)) {
        Ok(_) => println!("✅ Webhook processed successfully!"),
        Err(WebhookError::InvalidSignature) => {
            println!("❌ Invalid webhook signature!");
        }
        Err(e) => {
            println!("❌ Error processing webhook: {:?}", e);
        }
    }

    println!("\nProcessing without signature verification...");
    let simple_processor = WebhookProcessor::new().without_signature_verification();

    simple_processor.process(&mut handler, "ping", "{}", None)?;

    Ok(())
}
