use crate::common::utils::{
    get_user_id, are_friends, add_friendship, remove_friendship, with_csrf_validation, with_no_cache_headers,
    append_flash_message, get_user_id_from_jwt, setup_user_context, render_template, get_or_set_csrf_token,
};
use crate::notifications::{
    create_friend_request_notification, create_friend_accept_notification, create_friend_remove_notification,
};
use crate::try_or_handle;
use crate::common::prelude::*;
use actix_web::{web, HttpResponse, HttpRequest};
use crate::models::{CsrfForm, FriendRequest};
use serde_json::json;

pub async fn send_friend_request(
    data: web::Data<AppState>,
    form: web::Form<CsrfForm>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let friend_username = path.into_inner();

        let flash_redirect = |msg: &str| -> Result<HttpResponse, AppError> {
            let mut builder = HttpResponse::Found();
            let mut resp = builder.append_header(("Location", format!("/profile/{}", friend_username)));
            Ok(append_flash_message(&mut resp, msg, "error"))
        };

        let current_user_id_opt = get_user_id_from_jwt(&req, &jwt_secret)?;
        let current_user_id = match current_user_id_opt {
            Some(id) => id,
            None => return flash_redirect("Not logged in"),
        };

        log::info!("Sending friend request: user_id={}, friend_username={}", current_user_id, friend_username);

        let mut tx = data.db_pool.begin().await.map_err(AppError::Database)?;

        let friend_user_id_opt = get_user_id(&mut *tx, &friend_username).await?;
        let friend_user_id = match friend_user_id_opt {
            Some(id) => id,
            None => return flash_redirect("User not found"),
        };

        log::info!("Friend user_id: {}", friend_user_id);

        if current_user_id == friend_user_id {
            return flash_redirect("You cannot send a friend request to yourself");
        }

        if are_friends(&mut *tx, &current_user_id, &friend_user_id).await? {
            return flash_redirect("You are already friends");
        }

        let existing_request = sqlx::query!(
            "SELECT request_id, status FROM friend_requests WHERE sender_id = $1 AND receiver_id = $2",
            current_user_id,
            friend_user_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?;

        if let Some(request) = existing_request {
            match request.status.as_str() {
                "pending" => return flash_redirect("Friend request already sent and pending"),
                "declined" | "cancelled" => {
                    sqlx::query!(
                        "UPDATE friend_requests SET status = 'pending', created_at = NOW() WHERE request_id = $1",
                        request.request_id
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::Database)?;
                    log::info!("Updated existing friend request status to pending");
                }
                "accepted" => return flash_redirect("You are already friends"),
                _ => return flash_redirect("Friend request already exists"),
            }
        } else {
            sqlx::query!(
                "INSERT INTO friend_requests (sender_id, receiver_id, status, created_at) VALUES ($1, $2, 'pending', NOW())",
                current_user_id,
                friend_user_id
            )
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database)?;
            log::info!("Friend request inserted: sender_id={}, receiver_id={}", current_user_id, friend_user_id);
        }

        let current_username = sqlx::query!("SELECT username FROM users WHERE user_id = $1", current_user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::Database)?
            .username;

        create_friend_request_notification(&mut *tx, &friend_user_id, &current_user_id, &current_username).await?;

        log::info!("Notification created for friend request");

        tx.commit().await.map_err(AppError::Database)?;

        log::info!("Friend request transaction committed");

        let mut builder = HttpResponse::Found();
        let mut resp = builder.append_header(("Location", format!("/profile/{}", friend_username)));
        Ok(append_flash_message(&mut resp, "Friend request sent successfully", "success"))
    })
    .await
}

pub async fn respond_friend_request(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
    form: web::Json<CsrfForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let (sender_username, action) = path.into_inner();
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let current_user_id = try_or_handle!(
            get_user_id_from_jwt(&req, &jwt_secret)
                .map_err(|_| AppError::Unauthorized("Unauthorized access".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
            &data, &jwt_secret, &req
        );

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(
            pool.begin().await.map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        let sender_user_id = try_or_handle!(
            get_user_id(&mut *tx, &sender_username).await?
                .ok_or_else(|| AppError::NotFound("User not found".to_string())),
            &data, &jwt_secret, &req
        );

        let request = try_or_handle!(
            sqlx::query!(
                "SELECT request_id FROM friend_requests WHERE sender_id = $1 AND receiver_id = $2 AND status = 'pending'",
                sender_user_id,
                current_user_id
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        let request_id = if let Some(r) = request {
            r.request_id
        } else {
            return Err(AppError::BadRequest("No pending friend request found".to_string()));
        };

        match action.as_str() {
            "accept" => {
                try_or_handle!(add_friendship(&mut *tx, &sender_user_id, &current_user_id).await, &data, &jwt_secret, &req);

                try_or_handle!(
                    sqlx::query!("UPDATE friend_requests SET status = 'accepted' WHERE request_id = $1", request_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(AppError::Database),
                    &data, &jwt_secret, &req
                );

                let current_username = try_or_handle!(
                    sqlx::query!("SELECT username FROM users WHERE user_id = $1", current_user_id)
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(AppError::Database),
                    &data, &jwt_secret, &req
                ).username;

                try_or_handle!(
                    create_friend_accept_notification(&mut *tx, &sender_user_id, &current_user_id, &current_username).await,
                    &data, &jwt_secret, &req
                );

                try_or_handle!(
                    sqlx::query!(
                        "DELETE FROM notifications WHERE user_id = $1 AND notification_type = 'friend_request' AND related_user_id = $2",
                        current_user_id,
                        sender_user_id
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::Database),
                    &data, &jwt_secret, &req
                );
            }
            "decline" => {
                try_or_handle!(
                    sqlx::query!("UPDATE friend_requests SET status = 'declined' WHERE request_id = $1", request_id)
                        .execute(&mut *tx)
                        .await
                        .map_err(AppError::Database),
                    &data, &jwt_secret, &req
                );

                try_or_handle!(
                    sqlx::query!(
                        "DELETE FROM notifications WHERE user_id = $1 AND notification_type = 'friend_request' AND related_user_id = $2",
                        current_user_id,
                        sender_user_id
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::Database),
                    &data, &jwt_secret, &req
                );
            }
            _ => {
                return Err(AppError::BadRequest("Invalid action".to_string()));
            }
        }

        try_or_handle!(
            tx.commit().await.map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        Ok(HttpResponse::Ok().json(json!({
            "message": if action == "accept" { "Friend request accepted" } else { "Friend request declined" }
        })))
    }).await
}

pub async fn add_friend(
    data: web::Data<AppState>,
    form: web::Form<CsrfForm>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    send_friend_request(data, form, path, req, jwt_secret).await
}

pub async fn remove_friend(
    data: web::Data<AppState>,
    form: web::Form<CsrfForm>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let friend_username = path.into_inner();

        let current_user_id = try_or_handle!(
            get_user_id_from_jwt(&req, &jwt_secret)
                .map_err(|_| AppError::Unauthorized("Unauthorized access".to_string()))?
                .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
            &data, &jwt_secret, &req
        );

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(
            pool.begin().await.map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        let friend_user_id = try_or_handle!(
            get_user_id(&mut *tx, &friend_username).await?
                .ok_or_else(|| AppError::NotFound("User not found".to_string())),
            &data, &jwt_secret, &req
        );

        let deleted = try_or_handle!(
            remove_friendship(&mut *tx, &current_user_id, &friend_user_id).await,
            &data, &jwt_secret, &req
        );

        if !deleted {
            return Err(AppError::BadRequest("Not friends".to_string()));
        }

        try_or_handle!(
            sqlx::query!(
                r#"DELETE FROM friend_requests
                   WHERE ((sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1))
                     AND status IN ('pending', 'accepted', 'declined', 'cancelled')"#,
                current_user_id,
                friend_user_id
            )
            .execute(&mut *tx)
            .await
            .map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        let current_username = try_or_handle!(
            sqlx::query!("SELECT username FROM users WHERE user_id = $1", current_user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::Database),
            &data, &jwt_secret, &req
        ).username;

        try_or_handle!(
            create_friend_remove_notification(&mut *tx, &friend_user_id, &current_user_id, &current_username).await,
            &data, &jwt_secret, &req
        );

        try_or_handle!(
            tx.commit().await.map_err(AppError::Database),
            &data, &jwt_secret, &req
        );

        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", format!("/profile/{}", friend_username))),
            "Friend removed successfully",
            "success",
        ))
    }).await
}

pub async fn get_friend_requests(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id_opt = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret).map_err(|_| AppError::Unauthorized("Unauthorized access".to_string())),
        &data, &jwt_secret, &req
    );

    let current_user_id = try_or_handle!(
        user_id_opt.ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
        &data, &jwt_secret, &req
    );

    let pool = &data.db_pool;
    let friend_requests = try_or_handle!(
        sqlx::query_as!(
            FriendRequest,
            r#"
            SELECT fr.request_id, fr.sender_id, u.username as sender_username, fr.created_at
            FROM friend_requests fr
            JOIN users u ON fr.sender_id = u.user_id
            WHERE fr.receiver_id = $1 AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            "#,
            current_user_id
        )
        .fetch_all(pool)
        .await
        .map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    let mut context = Context::new();
    context.insert("friend_requests", &friend_requests);
    context.insert("site_name", "pastry");
    try_or_handle!(setup_user_context(&mut context, &data, &req, &jwt_secret).await, &data, &jwt_secret, &req);

    let mut response_builder = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

    context.insert("csrf_token", &csrf_token);

    let rendered = try_or_handle!(
        render_template(&data.tera, "user/friend_requests.html", &context),
        &data, &jwt_secret, &req
    );

    response_builder
        .content_type("text/html");

    Ok(response_builder.body(rendered))
}
