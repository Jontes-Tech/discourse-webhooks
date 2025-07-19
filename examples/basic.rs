use discourse_webhooks::{
    PostWebhookEvent, TopicWebhookEvent, WebhookEventHandler, WebhookProcessor,
};
use serde_json::json;

struct MyHandler;

impl WebhookEventHandler for MyHandler {
    type Error = String;

    fn handle_topic_created(&mut self, event: &TopicWebhookEvent) -> Result<(), Self::Error> {
        println!("New topic created: {}", event.topic.title);
        Ok(())
    }

    fn handle_post_created(&mut self, event: &PostWebhookEvent) -> Result<(), Self::Error> {
        println!("New post by {}: {}", event.post.username, event.post.raw);
        Ok(())
    }
}

fn main() {
    let processor = WebhookProcessor::new();
    let mut handler = MyHandler;

    let topic_payload = json!({
        "topic": {
            "archetype": "regular",
            "archived": false,
            "bookmarked": false,
            "category_id": 4,
            "closed": false,
            "created_at": "2025-07-19T12:09:30.763Z",
            "created_by": {
                "avatar_template": "/user_avatar/og.ax/jonte/{size}/3_2.png",
                "id": 2,
                "name": null,
                "username": "user1"
            },
            "deleted_at": null,
            "deleted_by": null,
            "fancy_title": "Example Topic",
            "featured_link": null,
            "has_deleted": false,
            "highest_post_number": 1,
            "id": 10,
            "last_posted_at": "2025-07-19T12:09:30.847Z",
            "last_poster": {
                "avatar_template": "/user_avatar/og.ax/jonte/{size}/3_2.png",
                "id": 2,
                "name": null,
                "username": "user1"
            },
            "like_count": 0,
            "participant_count": 1,
            "pinned": false,
            "pinned_at": null,
            "pinned_globally": false,
            "pinned_until": null,
            "posts_count": 1,
            "reply_count": 0,
            "slug": "example-topic",
            "tags": [],
            "tags_descriptions": {},
            "thumbnails": null,
            "title": "Example Topic",
            "unpinned": null,
            "user_id": 2,
            "views": 0,
            "visible": true,
            "word_count": 8
        }
    });

    if let Err(e) = processor.process_json(&mut handler, "topic_created", topic_payload, None) {
        eprintln!("Error processing webhook: {:?}", e);
    }
}
