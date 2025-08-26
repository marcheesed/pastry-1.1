use crate::common::constants::FRIENDS_PER_PAGE;
use crate::common::prelude::*;
use crate::common::utils::{
    are_friends, get_friends, get_user_id, get_user_id_from_jwt, get_user_profile,
    render_template, setup_user_context, is_user_admin, with_no_cache_headers,
    user_exists, validate_username, with_csrf_validation, append_flash_message, get_sanitizer,
    extract_flash_message, clear_flash_cookie, handle_error, handle_api_error, get_or_set_csrf_token,
};
use crate::try_or_handle;
use crate::models::{Friend, ProfileForm, CsrfForm, FlashMessage};
use sqlx::{PgPool, Row};
use chrono::Duration;
use sqlx::types::chrono::{DateTime, Utc};

pub struct ProfileFriendsData {
    user_id: String,
    username: String,
    display_name: Option<String>,
    bio: Option<String>,
    profile_picture_url: Option<String>,
    total_friends: u32,
    total_pages: u32,
    current_page: u32,
    friends: Vec<Friend>,
    badges: Vec<String>,
}

fn parse_profile_query_params(query: &str) -> Result<(bool, u32), AppError> {
    let query_params: web::Query<HashMap<String, String>> = web::Query::from_query(query)
        .map_err(|e| AppError::BadRequest(format!("Invalid query parameters: {}", e)))?;
    let edit_mode = query_params
        .get("edit")
        .map(|v| v == "true")
        .unwrap_or(false);
    let page: u32 = query_params
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    Ok((edit_mode, page))
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

pub async fn get_profile_friends_data(
    pool: &PgPool,
    username: &str,
    page: u32,
    friends_per_page: u32,
) -> Result<ProfileFriendsData, AppError> {
    let user_profile = get_user_profile(pool, username).await?
        .ok_or_else(|| AppError::NotFound(format!("User '{}' not found", username)))?;

    let (user_id, username, display_name, bio, profile_picture_url) = user_profile;

    let sanitized_bio = bio.map(|b| {
        let sanitizer = get_sanitizer();
        sanitizer.clean(&b).to_string()
    });

    let sanitized_display_name = display_name.map(|d| {
        let sanitizer = get_sanitizer();
        sanitizer.clean(&d).to_string()
    });

    let total_friends: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM users u
        JOIN friendships f ON (u.user_id = f.user_id1 OR u.user_id = f.user_id2)
        WHERE (f.user_id1 = $1 OR f.user_id2 = $2) AND u.user_id != $3
        "#,
    )
    .bind(&user_id)
    .bind(&user_id)
    .bind(&user_id)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)?;

    let total_friends = total_friends.0 as u32;

    let total_pages = (total_friends as f64 / friends_per_page as f64).ceil() as u32;
    let current_page = page.max(1).min(total_pages.max(1));
    let offset = (current_page - 1) * friends_per_page;

    let friends = get_friends(pool, &user_id, friends_per_page, offset).await?;
    let badges = get_user_badges(pool, &user_id).await?;

    Ok(ProfileFriendsData {
        user_id,
        username,
        display_name: sanitized_display_name,
        bio: sanitized_bio,
        profile_picture_url,
        total_friends,
        total_pages,
        current_page,
        friends,
        badges,
    })
}

pub async fn view_profile(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let username = path.into_inner();

    let (edit_mode, page) = try_or_handle!(
        parse_profile_query_params(req.query_string()),
        &data,
        &jwt_secret,
        &req
    );

    let current_user_id_opt = match get_user_id_from_jwt(&req, &jwt_secret) {
        Ok(opt) => opt,
        Err(e) => {
            log::warn!("Ignoring invalid JWT token: {:?}", e);
            None
        }
    };

    let profile_data = try_or_handle!(
        get_profile_friends_data(&data.db_pool, &username, page, FRIENDS_PER_PAGE).await,
        &data,
        &jwt_secret,
        &req
    );

    let is_own_profile = current_user_id_opt
        .as_ref()
        .map(|id| id == &profile_data.user_id)
        .unwrap_or(false);

    let is_admin = if let Some(current_user_id) = &current_user_id_opt {
        let mut conn = try_or_handle!(
            data.db_pool.acquire().await.map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );
        try_or_handle!(
            is_user_admin(&mut *conn, current_user_id).await,
            &data,
            &jwt_secret,
            &req
        )
    } else {
        false
    };

    if edit_mode && !is_own_profile && !is_admin {
        return crate::common::utils::handle_error(
            AppError::Forbidden("You are not authorized to edit this profile".to_string()), 
            &data, 
            &jwt_secret, 
            &req
        ).await;
    }

    let is_friend = if let Some(current_user_id) = &current_user_id_opt {
        if current_user_id != &profile_data.user_id {
            try_or_handle!(
                are_friends(&data.db_pool, current_user_id, &profile_data.user_id).await,
                &data,
                &jwt_secret,
                &req
            )
        } else {
            false
        }
    } else {
        false
    };

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = Context::new();
    context.insert("username", &profile_data.username);
    context.insert("display_name", &profile_data.display_name.as_ref().map(|s| s.as_str()));
    context.insert("bio", &profile_data.bio.as_ref().map(|s| s.as_str()));
    context.insert("profile_picture_url", &profile_data.profile_picture_url.as_ref().map(|s| s.as_str()));
    context.insert("edit_mode", &edit_mode);
    context.insert("friends", &profile_data.friends);
    context.insert("is_own_profile", &is_own_profile);
    context.insert("is_friend", &is_friend);
    context.insert("is_admin", &is_admin);
    context.insert("csrf_token", &csrf_token);
    context.insert("current_page", &profile_data.current_page);
    context.insert("total_pages", &profile_data.total_pages);
    context.insert("total_friends", &profile_data.total_friends);
    context.insert("badges", &profile_data.badges);

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    try_or_handle!(
        setup_user_context(&mut context, &data, &req, &jwt_secret).await,
        &data,
        &jwt_secret,
        &req
    );

    let template_name = if edit_mode {
        "user/edit_profile.html"
    } else {
        "user/profile.html"
    };

    let rendered = try_or_handle!(
        render_template(&data.tera, template_name, &context),
        &data,
        &jwt_secret,
        &req
    );

    response
        .content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

pub async fn api_profile_friends(
    data: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> Result<HttpResponse, AppError> {
    let username = path.into_inner();
    let page: u32 = query
        .get("page")
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);

    let profile_data = match get_profile_friends_data(&data.db_pool, &username, page, FRIENDS_PER_PAGE).await {
        Ok(data) => data,
        Err(err) => return handle_api_error(err).await,
    };

    let response_json = serde_json::json!({
        "friends": profile_data.friends,
        "page": profile_data.current_page,
        "total_pages": profile_data.total_pages,
        "total_friends": profile_data.total_friends,
        "has_next": profile_data.current_page < profile_data.total_pages,
        "has_prev": profile_data.current_page > 1,
        "badges": profile_data.badges,
        "display_name": profile_data.display_name,
    });

    Ok(HttpResponse::Ok().json(response_json))
}

pub async fn update_profile(
    data: web::Data<AppState>,
    path: web::Path<String>,
    form: web::Form<ProfileForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let target_username = path.into_inner();
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let current_user_id_opt = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);
        let current_user_id = match current_user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::Unauthorized("Not logged in".to_string()), &data, &jwt_secret, &req).await,
        };

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        let is_admin = try_or_handle!(is_user_admin(&mut *tx, &current_user_id).await, &data, &jwt_secret, &req);

        let target_user_id_opt = try_or_handle!(get_user_id(&mut *tx, &target_username).await, &data, &jwt_secret, &req);
        let target_user_id = match target_user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::NotFound(format!("User '{}' not found", target_username)), &data, &jwt_secret, &req).await,
        };

        if !is_admin && current_user_id != target_user_id {
            return handle_error(AppError::Forbidden("You can only edit your own profile".to_string()), &data, &jwt_secret, &req).await;
        }

        if form.action.as_deref() == Some("delete") {
            let deleted = try_or_handle!(
                sqlx::query("DELETE FROM users WHERE user_id = $1")
                    .bind(&target_user_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::from),
                &data,
                &jwt_secret,
                &req
            );

            if deleted.rows_affected() == 0 {
                return handle_error(AppError::NotFound("User not found".to_string()), &data, &jwt_secret, &req).await;
            }

            try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

            log::info!(
                "Profile deleted: user_id={}, deleted_by={}, is_admin={}",
                target_user_id,
                current_user_id,
                is_admin
            );

            let redirect_url = if is_admin { "/admin/users" } else { "/" };
            return Ok(append_flash_message(
                HttpResponse::Found()
                    .append_header(("Location", redirect_url))
                    .append_header(("Set-Cookie", "jwt_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT")),
                "Profile deleted successfully",
                "success",
            ));
        }

        let new_username = form.username.trim().to_string();
        let new_display_name = form.display_name.as_ref().map(|d| d.trim().to_string());
        let mut errors: HashMap<String, Vec<String>> = HashMap::new();

        // Validate display_name
        if let Some(display_name) = &new_display_name {
            if display_name.len() > 50 {
                errors.entry("display_name".to_string())
                    .or_default()
                    .push("Display name must be 50 characters or less".to_string());
            }
            if !display_name.is_empty() && !display_name.chars().all(|c| c.is_alphanumeric() || c.is_whitespace() || "!@#$%^&*()-_=+[]{}|;:,.<>?".contains(c)) {
                errors.entry("display_name".to_string())
                    .or_default()
                    .push("Display name contains invalid characters".to_string());
            }
        }

        if !is_admin {
            errors.extend(validate_username(&new_username));

            let row = try_or_handle!(
                sqlx::query("SELECT username, username_last_changed FROM users WHERE user_id = $1")
                    .bind(&target_user_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::from),
                &data,
                &jwt_secret,
                &req
            );

            let db_username: String = try_or_handle!(row.try_get("username").map_err(AppError::from), &data, &jwt_secret, &req);
            let last_changed: DateTime<Utc> = try_or_handle!(row.try_get("username_last_changed").map_err(AppError::from), &data, &jwt_secret, &req);

            if new_username != db_username {
                let last_changed_time = last_changed;
                let now = Utc::now();
                let two_weeks = Duration::weeks(2);
                if last_changed_time + two_weeks > now {
                    errors.entry("username".to_string())
                        .or_default()
                        .push("You can only change your username every two weeks".to_string());
                }

                if try_or_handle!(user_exists(&mut *tx, &new_username).await, &data, &jwt_secret, &req) {
                    errors.entry("username".to_string())
                        .or_default()
                        .push("Username already taken".to_string());
                }
            }
        }

        let sanitized_bio = form.bio.as_ref().map(|b| {
            let sanitizer = get_sanitizer();
            sanitizer.clean(b).to_string()
        });

        // Use username as display_name if display_name is empty or None
        let sanitized_display_name = match new_display_name {
            Some(ref display_name) if !display_name.is_empty() => {
                let sanitizer = get_sanitizer();
                Some(sanitizer.clean(display_name).to_string())
            }
            _ => Some(new_username.clone()), // Default to username if display_name is empty or None
        };

        if !errors.is_empty() {
            let mut response = with_no_cache_headers(HttpResponse::Ok());
            let csrf_token = get_or_set_csrf_token(&req, &mut response);

            let mut context = Context::new();
            context.insert("site_name", "pastry");
            context.insert("csrf_token", &csrf_token);
            try_or_handle!(setup_user_context(&mut context, &data, &req, &jwt_secret).await, &data, &jwt_secret, &req);
            context.insert("username", &new_username);
            context.insert("display_name", &sanitized_display_name);
            context.insert("profile_picture_url", &form.profile_picture_url);
            context.insert("bio", &sanitized_bio);
            context.insert("errors", &errors);
            context.insert("is_admin", &is_admin);

            let rendered = try_or_handle!(render_template(&data.tera, "user/edit_profile.html", &context), &data, &jwt_secret, &req);

            return Ok(response
                .content_type("text/html")
                .body(rendered));
        }

        if is_admin || new_username != target_username {
            try_or_handle!(
                sqlx::query(
                    "UPDATE users SET username = $1, username_last_changed = $2, display_name = $3, profile_picture_url = $4, bio = $5 WHERE user_id = $6"
                )
                .bind(&new_username)
                .bind(Utc::now())
                .bind(&sanitized_display_name)
                .bind(&form.profile_picture_url)
                .bind(&sanitized_bio)
                .bind(&target_user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
                &data,
                &jwt_secret,
                &req
            );
        } else {
            try_or_handle!(
                sqlx::query(
                    "UPDATE users SET display_name = $1, profile_picture_url = $2, bio = $3 WHERE user_id = $4"
                )
                .bind(&sanitized_display_name)
                .bind(&form.profile_picture_url)
                .bind(&sanitized_bio)
                .bind(&target_user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
                &data,
                &jwt_secret,
                &req
            );
        }

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

        log::info!(
            "Profile updated: user_id={}, updated_by={}, is_admin={}",
            target_user_id,
            current_user_id,
            is_admin
        );

        let redirect_url = format!("/profile/{}", new_username);
        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", redirect_url)),
            "Profile updated successfully",
            "success",
        ))
    }).await
}

pub async fn delete_profile_admin(
    data: web::Data<AppState>,
    path: web::Path<String>,
    form: web::Form<CsrfForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let target_username = path.into_inner();

        let current_user_id = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);

        let current_user_id = match current_user_id {
            Some(id) => id,
            None => return handle_error(AppError::Unauthorized("Not logged in".to_string()), &data, &jwt_secret, &req).await,
        };

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        let is_admin = try_or_handle!(is_user_admin(&mut *tx, &current_user_id).await, &data, &jwt_secret, &req);
        if !is_admin {
            return handle_error(AppError::Forbidden("Only admins can delete profiles".to_string()), &data, &jwt_secret, &req).await;
        }

        let target_user_id_opt = try_or_handle!(get_user_id(&mut *tx, &target_username).await, &data, &jwt_secret, &req);
        let target_user_id = match target_user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::NotFound(format!("User '{}' not found", target_username)), &data, &jwt_secret, &req).await,
        };

        let deleted = try_or_handle!(
            sqlx::query("DELETE FROM users WHERE user_id = $1")
                .bind(&target_user_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        if deleted.rows_affected() == 0 {
            return handle_error(AppError::NotFound("User not found".to_string()), &data, &jwt_secret, &req).await;
        }

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

        log::info!(
            "Profile deleted by admin: user_id={}, deleted_by={}",
            target_user_id,
            current_user_id
        );

        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", "/admin/users")),
            "Profile deleted successfully",
            "success",
        ))
    }).await
}

pub async fn assign_badge(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
    form: web::Form<CsrfForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let (username, badge_type) = path.into_inner();
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let current_user_id = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);

        let current_user_id = match current_user_id {
            Some(id) => id,
            None => return handle_error(AppError::Unauthorized("Not logged in".to_string()), &data, &jwt_secret, &req).await,
        };

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        let is_admin = try_or_handle!(is_user_admin(&mut *tx, &current_user_id).await, &data, &jwt_secret, &req);
        if !is_admin {
            return handle_error(AppError::Forbidden("Only admins can assign badges".to_string()), &data, &jwt_secret, &req).await;
        }

        let target_user_id_opt = try_or_handle!(get_user_id(&mut *tx, &username).await, &data, &jwt_secret, &req);
        let target_user_id = match target_user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::NotFound(format!("User '{}' not found", username)), &data, &jwt_secret, &req).await,
        };

        let valid_badges = vec!["staff", "donator", "tester", "contributor", "red_flag"];
        if !valid_badges.contains(&badge_type.as_str()) {
            return handle_error(AppError::BadRequest("Invalid badge type".to_string()), &data, &jwt_secret, &req).await;
        }

        try_or_handle!(
            sqlx::query(
                "INSERT INTO user_badges (user_id, badge_type) VALUES ($1, $2) ON CONFLICT DO NOTHING"
            )
            .bind(&target_user_id)
            .bind(&badge_type)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

        log::info!(
            "Badge assigned: user_id={}, badge_type={}, assigned_by={}",
            target_user_id,
            badge_type,
            current_user_id
        );

        let redirect_url = format!("/profile/{}", username);
        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", redirect_url)),
            &format!("Badge '{}' assigned successfully", badge_type),
            "success",
        ))
    }).await
}

pub async fn remove_badge(
    data: web::Data<AppState>,
    path: web::Path<(String, String)>,
    form: web::Form<CsrfForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let (username, badge_type) = path.into_inner();
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let current_user_id = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);
        let current_user_id = match current_user_id {
            Some(id) => id,
            None => return handle_error(AppError::Unauthorized("Not logged in".to_string()), &data, &jwt_secret, &req).await,
        };

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        let is_admin = try_or_handle!(is_user_admin(&mut *tx, &current_user_id).await, &data, &jwt_secret, &req);
        if !is_admin {
            return handle_error(AppError::Forbidden("Only admins can remove badges".to_string()), &data, &jwt_secret, &req).await;
        }

        let target_user_id_opt = try_or_handle!(get_user_id(&mut *tx, &username).await, &data, &jwt_secret, &req);
        let target_user_id = match target_user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::NotFound(format!("User '{}' not found", username)), &data, &jwt_secret, &req).await,
        };

        let valid_badges = vec!["staff", "donator", "tester", "contributor", "red_flag"];
        if !valid_badges.contains(&badge_type.as_str()) {
            return handle_error(AppError::BadRequest("Invalid badge type".to_string()), &data, &jwt_secret, &req).await;
        }

        let deleted = try_or_handle!(
            sqlx::query("DELETE FROM user_badges WHERE user_id = $1 AND badge_type = $2")
                .bind(&target_user_id)
                .bind(&badge_type)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        if deleted.rows_affected() == 0 {
            return handle_error(AppError::NotFound("Badge not found".to_string()), &data, &jwt_secret, &req).await;
        }

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

        log::info!(
            "Badge removed: user_id={}, badge_type={}, removed_by={}",
            target_user_id,
            badge_type,
            current_user_id
        );

        let redirect_url = format!("/profile/{}", username);
        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", redirect_url)),
            &format!("Badge '{}' removed successfully", badge_type),
            "success",
        ))
    }).await
}