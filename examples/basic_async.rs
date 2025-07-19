use discourse_webhooks::async_trait;
use discourse_webhooks::{PostWebhookEvent, WebhookEventHandler, WebhookProcessor};

struct MyHandler;

#[async_trait]
impl WebhookEventHandler for MyHandler {
    type Error = String;

    async fn handle_post_created(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        println!("New post by {}: {}", event.post.username, event.post.raw);
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    let processor = WebhookProcessor::new();
    let mut handler = MyHandler;

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
            "username": "jonte",
            "version": 1,
            "wiki": false
        }
    }"#;

    if let Err(e) = processor
        .process(&mut handler, "post_created", payload_str, None)
        .await
    {
        eprintln!("Error processing webhook: {:?}", e);
    }
}
