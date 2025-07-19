//! Event types and parsing for Discourse webhooks
//!
//! This module contains all the data structures that represent different
//! webhook events from Discourse, along with functions to parse them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Represents a user in webhook payloads
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookUser {
    /// Template URL for the user's avatar
    pub avatar_template: String,
    /// Unique user ID
    pub id: i32,
    /// Optional display name
    pub name: Option<String>,
    /// Username (unique identifier)
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TopicWebhookEvent {
    pub topic: WebhookTopic,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookTopic {
    pub archetype: String,
    pub archived: bool,
    pub bookmarked: bool,
    pub category_id: i32,
    pub closed: bool,
    pub created_at: DateTime<Utc>,
    pub created_by: WebhookUser,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<WebhookUser>,
    pub fancy_title: String,
    pub featured_link: Option<String>,
    pub has_deleted: bool,
    pub highest_post_number: i32,
    pub id: i32,
    pub last_posted_at: DateTime<Utc>,
    pub last_poster: WebhookUser,
    pub like_count: i32,
    pub participant_count: i32,
    pub pinned: bool,
    pub pinned_at: Option<DateTime<Utc>>,
    pub pinned_globally: bool,
    pub pinned_until: Option<DateTime<Utc>>,
    pub posts_count: i32,
    pub reply_count: i32,
    pub slug: String,
    pub tags: Vec<String>,
    pub tags_descriptions: serde_json::Value,
    pub thumbnails: Option<serde_json::Value>,
    pub title: String,
    pub unpinned: Option<DateTime<Utc>>,
    pub user_id: i32,
    pub views: i32,
    pub visible: bool,
    pub word_count: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PostWebhookEvent {
    pub post: WebhookPost,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebhookPost {
    pub admin: bool,
    pub avatar_template: String,
    pub bookmarked: bool,
    pub category_id: i32,
    pub category_slug: String,
    pub cooked: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub deleted_by: Option<WebhookUser>,
    pub display_username: Option<String>,
    pub edit_reason: Option<String>,
    pub flair_group_id: Option<i32>,
    pub flair_name: Option<String>,
    pub hidden: bool,
    pub id: i32,
    pub incoming_link_count: i32,
    pub moderator: bool,
    pub name: Option<String>,
    pub post_number: i32,
    pub post_type: i32,
    pub post_url: String,
    pub posts_count: i32,
    pub primary_group_name: Option<String>,
    pub quote_count: i32,
    pub raw: String,
    pub reads: i32,
    pub reply_count: i32,
    pub reply_to_post_number: Option<i32>,
    pub reviewable_id: Option<i32>,
    pub reviewable_score_count: i32,
    pub reviewable_score_pending_count: i32,
    pub score: f64,
    pub staff: bool,
    pub topic_archetype: String,
    pub topic_filtered_posts_count: i32,
    pub topic_id: i32,
    pub topic_posts_count: i32,
    pub topic_slug: String,
    pub topic_title: String,
    pub trust_level: i32,
    pub updated_at: DateTime<Utc>,
    pub user_deleted: bool,
    pub user_id: i32,
    pub user_title: Option<String>,
    pub username: String,
    pub version: i32,
    pub wiki: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WebhookEventPayload {
    TopicEvent(TopicWebhookEvent),
    PostEvent(PostWebhookEvent),
    // For events we don't have specific types for yet
    Generic(serde_json::Value),
}

pub fn parse_webhook_payload(
    event_type: &str,
    payload: serde_json::Value,
) -> Result<WebhookEventPayload, serde_json::Error> {
    match event_type {
        "topic_created" | "topic_edited" | "topic_destroyed" | "topic_recovered" => {
            let topic_event: TopicWebhookEvent = serde_json::from_value(payload)?;
            Ok(WebhookEventPayload::TopicEvent(topic_event))
        }
        "post_created" | "post_edited" | "post_destroyed" | "post_recovered" => {
            let post_event: PostWebhookEvent = serde_json::from_value(payload)?;
            Ok(WebhookEventPayload::PostEvent(post_event))
        }
        _ => Ok(WebhookEventPayload::Generic(payload)),
    }
}
