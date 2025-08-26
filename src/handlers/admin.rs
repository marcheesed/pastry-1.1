use crate::common::prelude::*;
use crate::common::utils::{
    get_user_id_from_jwt, render_template, setup_user_context, extract_flash_message,
    clear_flash_cookie, is_user_admin, append_flash_message, with_csrf_validation, with_no_cache_headers, get_or_set_csrf_token,
};
use crate::common::constants::{TEMPLATE_ADMIN_PANEL, TEMPLATE_ADMIN_PASTES, TEMPLATE_ADMIN_USERS};
use crate::try_or_handle;
use crate::models::FlashMessage;
use actix_web::{web, HttpRequest, HttpResponse};
use sqlx::{PgPool, Row};

#[derive(serde::Serialize)]
pub struct PasteSummary {
    pub token: String,
    pub owner_username: String,
}

#[derive(serde::Deserialize)]
pub struct AdminDeleteForm {
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct BanForm {
    pub username: String,
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct UnbanForm {
    pub username: String,
    pub csrf_token: String,
}

#[derive(serde::Deserialize)]
pub struct PaginationParams {
    page: Option<u32>,
}

async fn get_user_badges(pool: &PgPool, user_id: &str) -> Result<Vec<String>, AppError> {
    let badges = sqlx::query("SELECT badge_type FROM user_badges WHERE user_id = $1")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database)?
        .into_iter()
        .map(|row| row.get::<String, _>("badge_type"))
        .collect();
    Ok(badges)
}

pub async fn admin_panel(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
        &data,
        &jwt_secret,
        &req
    );

    let pool = &data.db_pool;

    try_or_handle!(
        if is_user_admin(pool, &user_id).await? {
            Ok(())
        } else {
            Err(AppError::Unauthorized("Admin access required".to_string()))
        },
        &data,
        &jwt_secret,
        &req
    );

    let mut context = tera::Context::new();
    context.insert("site_name", "pastry");

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);
    context.insert("csrf_token", &csrf_token);

    try_or_handle!(
        setup_user_context(&mut context, &data, &req, &jwt_secret).await,
        &data,
        &jwt_secret,
        &req
    );

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    let rendered = try_or_handle!(
        render_template(&data.tera, TEMPLATE_ADMIN_PANEL, &context),
        &data,
        &jwt_secret,
        &req
    );

    response.content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

pub async fn admin_pastes(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PaginationParams>,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit: u32 = 20;
    let offset = (page - 1) * limit;

    let user_id = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
        &data,
        &jwt_secret,
        &req
    );

    let pool = &data.db_pool;

    try_or_handle!(
        if is_user_admin(pool, &user_id).await? {
            Ok(())
        } else {
            Err(AppError::Unauthorized("Admin access required".to_string()))
        },
        &data,
        &jwt_secret,
        &req
    );

    let total_pastes: i64 = try_or_handle!(
        sqlx::query("SELECT COUNT(*) FROM pastes")
            .fetch_one(pool)
            .await
            .map_err(AppError::Database)
            .and_then(|row| row.try_get::<i64, _>(0).map_err(|e| AppError::Database(e.into()))),
        &data,
        &jwt_secret,
        &req
    );

    let pastes = try_or_handle!(
        sqlx::query_as::<_, (String, String, String)>(
            "SELECT p.token, p.user_id, u.username as owner_username
             FROM pastes p
             JOIN users u ON p.user_id = u.user_id
             ORDER BY p.timestamp DESC
             LIMIT $1 OFFSET $2"
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database),
        &data,
        &jwt_secret,
        &req
    );

    let pastes_data: Vec<PasteSummary> = pastes
        .into_iter()
        .map(|(token, _user_id, owner_username)| PasteSummary {
            token,
            owner_username,
        })
        .collect();

    let total_pages = ((total_pastes as f64) / (limit as f64)).ceil() as u32;

    let mut context = tera::Context::new();
    context.insert("site_name", "pastry");
    context.insert("pastes", &pastes_data);
    context.insert("current_page", &page);
    context.insert("total_pages", &total_pages);

    try_or_handle!(
        setup_user_context(&mut context, &data, &req, &jwt_secret).await,
        &data,
        &jwt_secret,
        &req
    );

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    let mut response = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(&req, &mut response);
    context.insert("csrf_token", &csrf_token);

    let rendered = try_or_handle!(
        render_template(&data.tera, TEMPLATE_ADMIN_PASTES, &context),
        &data,
        &jwt_secret,
        &req
    );

    response.content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

pub async fn admin_delete_paste(
    data: web::Data<AppState>,
    path: web::Path<String>,
    form: web::Form<AdminDeleteForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    let form_csrf_token = form.csrf_token.clone();

    with_csrf_validation(req.clone(), &form_csrf_token, || async {
        let user_id = try_or_handle!(
            get_user_id_from_jwt(&req, &jwt_secret)?
                .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
            &data,
            &jwt_secret,
            &req
        );

        let pool = &data.db_pool;
        try_or_handle!(
            if is_user_admin(pool, &user_id).await? {
                Ok(())
            } else {
                Err(AppError::Unauthorized("Admin access required".to_string()))
            },
            &data,
            &jwt_secret,
            &req
        );

        super::paste::handle_delete_action(&data, &token, &user_id).await
    })
    .await
}

pub async fn admin_users(
    data: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<PaginationParams>,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let limit: u32 = 20;
    let offset = (page - 1) * limit;

    let user_id = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
        &data,
        &jwt_secret,
        &req
    );

    let pool = &data.db_pool;

    try_or_handle!(
        if is_user_admin(pool, &user_id).await? {
            Ok(())
        } else {
            Err(AppError::Unauthorized("Admin access required".to_string()))
        },
        &data,
        &jwt_secret,
        &req
    );

    let total_users: i64 = try_or_handle!(
        sqlx::query("SELECT COUNT(*) FROM users")
            .fetch_one(pool)
            .await
            .map_err(AppError::Database)
            .and_then(|row| row.try_get::<i64, _>(0).map_err(|e| AppError::Database(e.into()))),
        &data,
        &jwt_secret,
        &req
    );

    let users_data = try_or_handle!(
        sqlx::query_as::<_, (String, String, bool, String)>(
            "SELECT user_id, username, banned, role FROM users ORDER BY username LIMIT $1 OFFSET $2"
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await
        .map_err(AppError::Database),
        &data,
        &jwt_secret,
        &req
    );

    let mut users = Vec::new();
    for (user_id, username, banned, role) in users_data {
        let badges = try_or_handle!(
            get_user_badges(pool, &user_id).await,
            &data,
            &jwt_secret,
            &req
        );
        users.push((username, banned, role, badges));
    }

    let total_pages = ((total_users as f64) / (limit as f64)).ceil() as u32;

    let mut response = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = tera::Context::new();
    context.insert("site_name", "pastry");
    context.insert("csrf_token", &csrf_token);
    context.insert("users", &users);
    context.insert("current_page", &page);
    context.insert("total_pages", &total_pages);

    try_or_handle!(
        setup_user_context(&mut context, &data, &req, &jwt_secret).await,
        &data,
        &jwt_secret,
        &req
    );

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    let rendered = try_or_handle!(
        render_template(&data.tera, TEMPLATE_ADMIN_USERS, &context),
        &data,
        &jwt_secret,
        &req
    );

    response.content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

pub async fn ban_user(
    data: web::Data<AppState>,
    form: web::Form<BanForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = &form.csrf_token;
    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let user_id = try_or_handle!(
            get_user_id_from_jwt(&req, &jwt_secret)?
                .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
            &data,
            &jwt_secret,
            &req
        );

        let pool = &data.db_pool;

        try_or_handle!(
            if is_user_admin(pool, &user_id).await? {
                Ok(())
            } else {
                Err(AppError::Unauthorized("Admin access required".to_string()))
            },
            &data,
            &jwt_secret,
            &req
        );

        let username = form.username.trim();

        if username.is_empty() {
            return try_or_handle!(
                Err(AppError::Validation("Username cannot be empty".to_string())),
                &data,
                &jwt_secret,
                &req
            );
        }

        let rows_affected = try_or_handle!(
            sqlx::query("UPDATE users SET banned = TRUE WHERE username = $1")
                .bind(username)
                .execute(pool)
                .await
                .map_err(AppError::Database),
            &data,
            &jwt_secret,
            &req
        )
        .rows_affected();

        if rows_affected == 0 {
            return try_or_handle!(
                Err(AppError::Validation("User not found".to_string())),
                &data,
                &jwt_secret,
                &req
            );
        }

        Ok(append_flash_message(
            HttpResponse::Found().append_header(("Location", TEMPLATE_ADMIN_USERS)),
            &format!("User {} banned successfully", username),
            "success",
        ))
    })
    .await
}

pub async fn unban_user(
    data: web::Data<AppState>,
    form: web::Form<UnbanForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = &form.csrf_token;
    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let user_id = try_or_handle!(
            get_user_id_from_jwt(&req, &jwt_secret)?
                .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string())),
            &data,
            &jwt_secret,
            &req
        );

        let pool = &data.db_pool;

        try_or_handle!(
            if is_user_admin(pool, &user_id).await? {
                Ok(())
            } else {
                Err(AppError::Unauthorized("Admin access required".to_string()))
            },
            &data,
            &jwt_secret,
            &req
        );

        let username = form.username.trim();
        if username.is_empty() {
            return try_or_handle!(
                Err(AppError::Validation("Username cannot be empty".to_string())),
                &data,
                &jwt_secret,
                &req
            );
        }

        let rows_affected = try_or_handle!(
            sqlx::query("UPDATE users SET banned = FALSE WHERE username = $1")
                .bind(username)
                .execute(pool)
                .await
                .map_err(AppError::Database),
            &data,
            &jwt_secret,
            &req
        )
        .rows_affected();

        if rows_affected == 0 {
            return try_or_handle!(
                Err(AppError::Validation("User not found".to_string())),
                &data,
                &jwt_secret,
                &req
            );
        }

        Ok(append_flash_message(
            HttpResponse::Found().append_header(("Location", TEMPLATE_ADMIN_USERS)),
            &format!("User {} unbanned successfully", username),
            "success",
        ))
    })
    .await
}