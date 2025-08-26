use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// users
#[derive(Deserialize)]
pub struct RegisterForm {
    pub csrf_token: Option<String>,
    pub username: String,
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub csrf_token: Option<String>,
    pub username: String,   // public identifier to find user record
    pub user_token: String, // secret token acting like a password
}

#[derive(Deserialize)]
pub struct ProfileForm {
    pub csrf_token: Option<String>,
    pub username: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub profile_picture_url: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TemplateUser {
    pub username: String,
    pub profile_picture_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct Friend {
    pub username: String,
    pub profile_picture_url: Option<String>,
}

// pastes
#[derive(Deserialize)]
pub struct FormData {
    pub csrf_token: Option<String>,
    pub custom_token: Option<String>,
    pub content: String,
    pub css: Option<String>,
}

#[derive(Deserialize)]
pub struct EditForm {
    pub csrf_token: Option<String>,
    pub content: Option<String>,
    pub css: Option<String>,
    pub action: Option<PasteAction>,
    pub new_owner_username: Option<String>,
    pub collaborators_usernames: Option<String>,
    pub page_title: Option<String>,
    pub favicon_url: Option<String>,
    pub embed_description: Option<String>,
    pub embed_image_url: Option<String>,
    pub embed_color: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PasteAction {
    Save,
    Delete,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Paste {
    pub token: String,
    pub content: String,
    pub css: String,
    pub timestamp: DateTime<Utc>,
    pub edit_timestamp: DateTime<Utc>,
    pub user_id: String,
    pub views: i32,
    pub page_title: Option<String>,
    pub favicon_url: Option<String>,
    pub embed_description: Option<String>,
    pub embed_image_url: Option<String>,
    pub embed_color: Option<String>,
}

// dashboard
#[derive(Deserialize)]
pub struct DashboardQuery {
    pub page: Option<usize>,
    pub search: Option<String>,
    pub sort: Option<String>,
}

// friendship
#[derive(sqlx::FromRow, Serialize)]
pub struct FriendRequest {
    pub request_id: i32,
    pub sender_id: String,
    pub sender_username: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct Notification {
    pub notification_id: i32,
    pub user_id: String,
    pub notification_type: String,
    pub related_user_id: Option<String>,
    pub related_username: Option<String>,
    pub message: String,
    pub is_read: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// csrf
#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf_token: Option<String>,
}

// flash messages
#[derive(serde::Serialize)]
pub struct FlashMessage {
    pub level: String,
    pub message: String,
}
