use crate::common::utils::{get_sanitizer, get_user_id_from_jwt,};
use crate::common::prelude::*;
use crate::try_or_handle;
use crate::common::error::AppError;
use crate::models::Notification;
use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, PgConnection};
use serde_json::json;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, 
    exp: usize,
}

pub async fn get_notifications_api(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
    .ok_or_else(|| AppError::Unauthorized("Unauthorized: JWT token cookie missing or invalid".to_string()))?;

    let pool = &data.db_pool;

    let notifications = try_or_handle!(
        get_notifications(pool, &user_id).await,
        &data, &jwt_secret, &req
    );

    Ok(HttpResponse::Ok().json(notifications))
}

pub async fn mark_notifications_read(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid Authorization header".to_string()))?;

    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))?;

    let user_id = token_data.claims.sub;

    let pool = &data.db_pool;

    let mut tx = try_or_handle!(
        pool.begin().await.map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    try_or_handle!(
        sqlx::query!(
            "DELETE FROM notifications WHERE user_id = $1 AND notification_type = 'friend_accept'",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    try_or_handle!(
        sqlx::query!(
            "UPDATE notifications SET is_read = true WHERE user_id = $1 AND is_read = false",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    try_or_handle!(
        tx.commit().await.map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    Ok(HttpResponse::Ok().json(json!({ "message": "Notifications processed" })))
}

pub async fn dismiss_all_notifications(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_jwt(&req, &jwt_secret)?
    .ok_or_else(|| AppError::Unauthorized("Unauthorized: JWT token cookie missing or invalid".to_string()))?;

    let pool = &data.db_pool;

    let mut tx = try_or_handle!(
        pool.begin().await.map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    try_or_handle!(
        sqlx::query!(
            "DELETE FROM notifications 
             WHERE user_id = $1 
               AND notification_type IN ('friend_accept', 'friend_remove')",
            user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    try_or_handle!(
        tx.commit().await.map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    Ok(HttpResponse::Ok().json(json!({ "message": "Dismissed notifications" })))
}

pub async fn get_notifications(
    pool: &PgPool,
    user_id: &str,
) -> Result<Vec<Notification>, AppError> {
    let notifications = sqlx::query_as!(
        Notification,
        r#"
        SELECT 
            n.notification_id, 
            n.user_id, 
            n.notification_type, 
            n.related_user_id,
            u.username as "related_username?",
            n.message, 
            n.is_read, 
            n.created_at
        FROM notifications n
        LEFT JOIN users u ON n.related_user_id = u.user_id
        LEFT JOIN friend_requests fr ON n.related_user_id = fr.sender_id 
            AND n.user_id = fr.receiver_id 
            AND fr.status = 'pending'
            AND n.notification_type = 'friend_request'
        WHERE n.user_id = $1 
            AND (n.notification_type != 'friend_request' OR fr.request_id IS NOT NULL)
        ORDER BY n.created_at DESC
        "#,
        user_id
    )
    .fetch_all(pool)
    .await
    .map_err(AppError::Database)?;
    Ok(notifications)
}

pub async fn create_friend_request_notification(
    conn: &mut PgConnection,
    receiver_id: &str,
    sender_user_id: &str,
    sender_username: &str,
) -> Result<(), AppError> {
    let msg = format!("{} sent you a friend request", get_sanitizer().clean(sender_username));
    sqlx::query!(
        r#"INSERT INTO notifications (user_id, notification_type, related_user_id, message)
           VALUES ($1, 'friend_request', $2, $3)"#,
        receiver_id,
        sender_user_id,
        msg
    )
    .execute(conn)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

pub async fn create_friend_accept_notification(
    conn: &mut PgConnection,
    sender_id: &str,
    receiver_user_id: &str,
    receiver_username: &str,
) -> Result<(), AppError> {
    let msg = format!("{} accepted your friend request", get_sanitizer().clean(receiver_username));
    sqlx::query!(
        r#"INSERT INTO notifications (user_id, notification_type, related_user_id, message)
           VALUES ($1, 'friend_accept', $2, $3)"#,
        sender_id,
        receiver_user_id,
        msg
    )
    .execute(conn)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

pub async fn create_friend_remove_notification(
    conn: &mut PgConnection,
    receiver_id: &str,
    remover_user_id: &str,
    remover_username: &str,
) -> Result<(), AppError> {
    let msg = format!("{} removed you as a friend", get_sanitizer().clean(remover_username));
    sqlx::query!(
        r#"INSERT INTO notifications (user_id, notification_type, related_user_id, message)
           VALUES ($1, 'friend_remove', $2, $3)"#,
        receiver_id,
        remover_user_id,
        msg
    )
    .execute(conn)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}