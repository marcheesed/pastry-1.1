use crate::common::constants::{
    ALLOWED_CHARS, EDIT_PASTE_URL_PREFIX, MAX_TOKEN_ATTEMPTS, RESERVED_TOKENS, SAVE_PASTE_URL,
    TEMPLATE_EDIT_PASTE, TEMPLATE_PASTE_FORM, TEMPLATE_PASTE_VIEW, TOKEN_LENGTH,
};
use crate::common::prelude::*;
use crate::common::utils::{
    get_paste_by_token, get_sanitizer, get_user_id_from_jwt, get_or_set_csrf_token,
    render_404, render_template, setup_edit_paste_context, with_no_cache_headers,
    setup_view_paste_context, validate_paste_content, validate_meta_inputs, with_csrf_validation,
    is_user_admin, append_flash_message, extract_flash_message, clear_flash_cookie, handle_error,
};
use crate::try_or_handle;
use crate::models::{EditForm, FormData, Paste, PasteAction, FlashMessage};
use rand::rngs::OsRng;
use rand::distributions::{Distribution, Slice};
use actix_web::cookie::{Cookie, time::Duration};
use sqlx::{Postgres, Transaction, Row};
use chrono::{DateTime, Utc};

// renders the paste creation form
pub async fn index(
    data: web::Data<AppState>,
    jwt_secret: web::Data<String>,
    req: HttpRequest,
) -> Result<HttpResponse, AppError> {
    let mut context = tera::Context::new();
    context.insert("site_name", "pastry");
    context.insert("save_paste_url", SAVE_PASTE_URL);

    try_or_handle!(
        setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
        &data,
        &jwt_secret,
        &req
    );

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);
    context.insert("csrf_token", &csrf_token);

    let rendered = try_or_handle!(
        render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
        &data,
        &jwt_secret,
        &req
    );

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    response.content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

pub async fn token_exists(db_pool: &sqlx::PgPool, token: &str) -> Result<bool, AppError> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pastes WHERE token = $1")
        .bind(token)
        .fetch_one(db_pool)
        .await
        .map_err(AppError::Database)?;
    Ok(count.0 > 0)
}

pub fn validate_custom_token(token: &str) -> Result<(), AppError> {
    let token_len = token.len();
    if token_len < 2 || token_len > 20 {
        return Err(AppError::Validation(
            "Custom URL must be between 2 and 20 characters".to_string(),
        ));
    }
    if !token.bytes().all(|b| ALLOWED_CHARS.contains(&b)) {
        return Err(AppError::Validation(
            "Custom URL contains invalid characters".to_string(),
        ));
    }

    let token_lower = token.to_lowercase();
    if RESERVED_TOKENS.iter().any(|&r| r.eq_ignore_ascii_case(&token_lower)) {
        return Err(AppError::Validation(
            "Custom URL is reserved and cannot be used".to_string(),
        ));
    }

    Ok(())
}

pub async fn generate_random_token(db_pool: &sqlx::PgPool) -> Result<String, AppError> {
    let mut rng = OsRng;
    let distr = Slice::new(ALLOWED_CHARS).unwrap();

    for _ in 0..MAX_TOKEN_ATTEMPTS {
        let token: String = (0..TOKEN_LENGTH)
            .map(|_| *distr.sample(&mut rng) as char)
            .collect();
        if RESERVED_TOKENS.iter().any(|&r| r.eq_ignore_ascii_case(&token)) {
            continue;
        }
        if !token_exists(db_pool, &token).await? {
            return Ok(token);
        }
    }

    Err(AppError::Validation(
        "Failed to generate a unique token after several attempts".to_string(),
    ))
}

pub async fn is_main_owner<'e, E>(
    executor: E,
    paste_token: &str,
    user_id: &str,
) -> Result<bool, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM pastes WHERE token = $1 AND user_id = $2"
    )
    .bind(paste_token)
    .bind(user_id)
    .fetch_one(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(count.0 > 0)
}

pub async fn is_collaborator<'e, E>(
    executor: E,
    paste_token: &str,
    user_id: &str,
) -> Result<bool, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM paste_collaborators WHERE paste_token = $1 AND user_id = $2"
    )
    .bind(paste_token)
    .bind(user_id)
    .fetch_one(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(count.0 > 0)
}

async fn validate_and_get_paste(
    data: &web::Data<AppState>,
    token: &str,
    req: &HttpRequest,
    jwt_secret: &web::Data<String>,
) -> Result<(Paste, String), AppError> {
    let user_id = get_user_id_from_jwt(req, jwt_secret)?
        .ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))?;

    let paste = get_paste_by_token(&data.db_pool, token)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    Ok((paste, user_id))
}

pub async fn update_paste_content(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    content: &str,
    css: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE pastes SET content = $1, css = $2, edit_timestamp = $3 WHERE token = $4"
    )
    .bind(content)
    .bind(css)
    .bind(Utc::now())
    .bind(token)
    .execute(&mut **tx)
    .await
    .map_err(AppError::Database)?;

    sqlx::query(
        "UPDATE pastes_fts SET content_tsv = to_tsvector('english', $1) WHERE token = $2"
    )
    .bind(content)
    .bind(token)
    .execute(&mut **tx)
    .await
    .map_err(AppError::Database)?;

    Ok(())
}

pub async fn update_paste_metadata(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    page_title: Option<&str>,
    favicon_url: Option<&str>,
    embed_description: Option<&str>,
    embed_image_url: Option<&str>,
    embed_color: Option<&str>,
) -> Result<(), AppError> {
    let current_paste = get_paste_by_token(&mut **tx, token)
        .await?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?;

    let page_title = page_title
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| current_paste.page_title);
    let favicon_url = favicon_url
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| current_paste.favicon_url);
    let embed_description = embed_description
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| current_paste.embed_description);
    let embed_image_url = embed_image_url
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| current_paste.embed_image_url);
    let embed_color = embed_color
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| current_paste.embed_color);

    sqlx::query(
        "UPDATE pastes SET page_title = $1, favicon_url = $2, embed_description = $3, embed_image_url = $4, embed_color = $5 WHERE token = $6"
    )
    .bind(page_title)
    .bind(favicon_url)
    .bind(embed_description)
    .bind(embed_image_url)
    .bind(embed_color)
    .bind(token)
    .execute(&mut **tx)
    .await
    .map_err(AppError::Database)?;
    Ok(())
}

pub async fn update_ownership(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    new_owner_username: Option<&String>,
) -> Result<(), AppError> {
    if let Some(username) = new_owner_username
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let row = sqlx::query("SELECT user_id FROM users WHERE username = $1")
            .bind(username)
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| AppError::Validation("New owner username does not exist".to_string()))?;

        let new_owner_user_id: String = row.try_get("user_id").map_err(AppError::Database)?;

        sqlx::query("UPDATE pastes SET user_id = $1 WHERE token = $2")
            .bind(&new_owner_user_id)
            .bind(token)
            .execute(&mut **tx)
            .await
            .map_err(AppError::Database)?;
    }
    Ok(())
}

pub async fn update_collaborators(
    tx: &mut Transaction<'_, Postgres>,
    token: &str,
    paste_user_id: &str,
    collaborators_str: Option<&String>,
) -> Result<(), AppError> {
    // delete existing collaborators
    sqlx::query("DELETE FROM paste_collaborators WHERE paste_token = $1")
        .bind(token)
        .execute(&mut **tx)
        .await
        .map_err(AppError::Database)?;

    if let Some(collaborators) = collaborators_str {
        let usernames: Vec<&str> = collaborators
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        // get user IDs for the provided usernames
        let mut collaborator_ids: Vec<String> = Vec::new();
        for username in usernames {
            let row = sqlx::query("SELECT user_id FROM users WHERE username = $1")
                .bind(username)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::Database)?;

            match row {
                Some(row) => {
                    let user_id: String = row
                        .try_get("user_id")
                        .map_err(AppError::Database)?;
                    collaborator_ids.push(user_id);
                }
                None => {
                    return Err(AppError::Validation(format!(
                        "Username '{}' does not exist",
                        username
                    )));
                }
            }
        }

        // insert new collaborators, excluding the paste's main owner
        for id in collaborator_ids {
            if id != paste_user_id {
                sqlx::query("INSERT INTO paste_collaborators (paste_token, user_id) VALUES ($1, $2)")
                    .bind(token)
                    .bind(&id)
                    .execute(&mut **tx)
                    .await
                    .map_err(AppError::Database)?;
            }
        }
    }
    Ok(())
}

pub async fn handle_save_action(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    token: &str,
    req: HttpRequest,
    paste: &Paste,
    form: EditForm,
    is_main_owner: bool,
    is_admin: bool,
) -> Result<HttpResponse, AppError> {
    if let Err(e) = validate_paste_content(form.content.as_deref().unwrap_or(""), form.css.as_deref()) {
        let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
        let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

        let mut context = Context::new();
        context.insert("token", token);
        context.insert("paste", &paste.content);
        context.insert("css", &paste.css);
        context.insert("can_edit", &true);
        context.insert("edit_paste_url", &format!("{}{}", EDIT_PASTE_URL_PREFIX, token));
        context.insert("csrf_token", &csrf_token);
        context.insert("errors", &HashMap::from([("form".to_string(), vec![e.to_string()])]));
        context.insert("page_title", &paste.page_title);
        context.insert("favicon_url", &paste.favicon_url);
        context.insert("embed_description", &paste.embed_description);
        context.insert("embed_image_url", &paste.embed_image_url);
        context.insert("embed_color", &paste.embed_color);

        setup_edit_paste_context(&mut context, &data, &jwt_secret, &req, &mut response_builder, &paste).await?;

        let body = render_template(&data.tera, TEMPLATE_EDIT_PASTE, &context)?;

        response_builder.content_type("text/html");

        clear_flash_cookie(&mut response_builder);

        return Ok(response_builder.body(body));
    }

    validate_meta_inputs(
        &form.page_title,
        &form.favicon_url,
        &form.embed_description,
        &form.embed_image_url,
        &form.embed_color,
    )?;

    let content = get_sanitizer().clean(form.content.as_deref().unwrap_or("")).to_string();
    let css = form.css.as_deref().unwrap_or("").to_string();
    let pool = &data.db_pool;
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    update_paste_content(&mut tx, token, &content, &css).await?;

    update_paste_metadata(
        &mut tx, 
        token, 
        form.page_title.as_deref(), 
        form.favicon_url.as_deref(),
        form.embed_description.as_deref(),
        form.embed_image_url.as_deref(),
        form.embed_color.as_deref()
    ).await?;

    if is_main_owner || is_admin {
        update_ownership(&mut tx, token, form.new_owner_username.as_ref()).await?;
        update_collaborators(
            &mut tx,
            token,
            &paste.user_id,
            form.collaborators_usernames.as_ref(),
        ).await?;
    } else if form.new_owner_username.is_some() || form.collaborators_usernames.is_some() {
        return Err(AppError::Unauthorized(
            "Only the main owner or admin can change owner or collaborators".to_string(),
        ));
    }

    tx.commit().await.map_err(AppError::Database)?;

    Ok(
        append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", format!("/{}", token))),
            "Paste updated successfully",
            "success",
        )
    )
}

pub async fn handle_delete_action(
    data: &web::Data<AppState>,
    token: &str,
    user_id: &str,
) -> Result<HttpResponse, AppError> {
    let pool = &data.db_pool;
    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    let is_main_owner = is_main_owner(&mut *tx, token, user_id).await?;
    let is_admin = is_user_admin(&mut *tx, user_id).await?;
    if !is_main_owner && !is_admin {
        return Err(AppError::Unauthorized(
            "Only the main owner or admin can delete this paste".to_string(),
        ));
    }

    sqlx::query("DELETE FROM pastes WHERE token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    sqlx::query("DELETE FROM pastes_fts WHERE token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    sqlx::query("DELETE FROM paste_collaborators WHERE paste_token = $1")
        .bind(token)
        .execute(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(
        append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", "/")),
            "Paste deleted successfully",
            "success",
        )
    )
}

// saves a new paste to the db
pub async fn save_paste(
    data: web::Data<AppState>,
    form: web::Form<FormData>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");
    with_csrf_validation(req.clone(), form_csrf_token, || async {
        if let Err(e) = validate_paste_content(&form.content, form.css.as_deref()) {
            let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
            let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

            let mut context = Context::new();
            context.insert("site_name", "pastry");
            context.insert("save_paste_url", SAVE_PASTE_URL);
            context.insert("csrf_token", &csrf_token);
            context.insert("content", &form.content);
            context.insert("css", form.css.as_deref().unwrap_or(""));
            context.insert("custom_token", form.custom_token.as_deref().unwrap_or(""));
            context.insert("errors", &HashMap::from([("form".to_string(), vec![e.to_string()])]));
            try_or_handle!(
                setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
                &data,
                &jwt_secret,
                &req
            );
            let rendered = try_or_handle!(
                render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
                &data,
                &jwt_secret,
                &req
            );

            response_builder.content_type("text/html");
            clear_flash_cookie(&mut response_builder);

            return Ok(response_builder.body(rendered));
        }

        let user_id_opt = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);
        let user_id = match user_id_opt {
            Some(id) => id,
            None => return handle_error(AppError::Unauthorized("User not logged in".to_string()), &data, &jwt_secret, &req).await,
        };

        let pool = &data.db_pool;
        let mut tx = try_or_handle!(pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        let user_exists = try_or_handle!(
            sqlx::query("SELECT 1 FROM users WHERE user_id = $1")
                .bind(&user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        )
        .is_some();

        if !user_exists {
            return Err(AppError::Unauthorized("Invalid user session. Please log in again.".to_string()));
        }

        let total_paste_count: (i64,) = try_or_handle!(
            sqlx::query_as("SELECT COUNT(*) FROM pastes WHERE user_id = $1")
                .bind(&user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );
        
        if total_paste_count.0 >= 250 {
            let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
            let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

            let mut context = Context::new();
            context.insert("site_name", "pastry");
            context.insert("save_paste_url", SAVE_PASTE_URL);
            context.insert("csrf_token", &csrf_token);
            context.insert("content", &form.content);
            context.insert("css", form.css.as_deref().unwrap_or(""));
            context.insert("custom_token", form.custom_token.as_deref().unwrap_or(""));
            context.insert(
                "flash_messages",
                &vec![FlashMessage {
                    level: "error".to_string(),
                    message: "You have reached the maximum limit of 250 pastes".to_string(),
                }],
            );

            try_or_handle!(
                setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
                &data,
                &jwt_secret,
                &req
            );
            let rendered = try_or_handle!(
                render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
                &data,
                &jwt_secret,
                &req
            );

            response_builder.content_type("text/html");
            clear_flash_cookie(&mut response_builder);

            return Ok(response_builder.body(rendered));
        }

        let start_of_day = Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap();
        let start_of_day: DateTime<Utc> = DateTime::from_naive_utc_and_offset(start_of_day, Utc);
        let daily_paste_count: (i64,) = try_or_handle!(
            sqlx::query_as("SELECT COUNT(*) FROM pastes WHERE user_id = $1 AND timestamp >= $2")
                .bind(&user_id)
                .bind(start_of_day)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        if daily_paste_count.0 >= 10 {
            let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
            let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

            let mut context = Context::new();
            context.insert("site_name", "pastry");
            context.insert("save_paste_url", SAVE_PASTE_URL);
            context.insert("csrf_token", &csrf_token);
            context.insert("content", &form.content);
            context.insert("css", form.css.as_deref().unwrap_or(""));
            context.insert("custom_token", form.custom_token.as_deref().unwrap_or(""));
            context.insert(
                "flash_messages",
                &vec![FlashMessage {
                    level: "error".to_string(),
                    message: "You have reached the daily limit of 10 pastes".to_string(),
                }],
            );

            try_or_handle!(
                setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
                &data,
                &jwt_secret,
                &req
            );
            let rendered = try_or_handle!(
                render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
                &data,
                &jwt_secret,
                &req
            );

            response_builder.content_type("text/html");
            clear_flash_cookie(&mut response_builder);

            return Ok(response_builder.body(rendered));
        }

        let content = get_sanitizer().clean(&form.content).to_string();
        let css = form.css.as_deref().unwrap_or("").to_string();
        let token = if let Some(custom_token) = &form.custom_token {
            let custom_token = custom_token.trim();
            if !custom_token.is_empty() {
                match validate_custom_token(custom_token) {
                    Ok(_) => {
                        if try_or_handle!(token_exists(&pool, custom_token).await, &data, &jwt_secret, &req) {
                            let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
                            let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

                            let mut context = Context::new();
                            context.insert("site_name", "pastry");
                            context.insert("save_paste_url", SAVE_PASTE_URL);
                            context.insert("csrf_token", &csrf_token);
                            context.insert("content", &form.content);
                            context.insert("css", &css);
                            context.insert("custom_token", custom_token);
                            context.insert(
                                "flash_messages",
                                &vec![FlashMessage {
                                    level: "error".to_string(),
                                    message: "Custom URL is already taken".to_string(),
                                }],
                            );

                            try_or_handle!(
                                setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
                                &data,
                                &jwt_secret,
                                &req
                            );
                            let rendered = try_or_handle!(
                                render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
                                &data,
                                &jwt_secret,
                                &req
                            );

                            response_builder.content_type("text/html");
                            clear_flash_cookie(&mut response_builder);

                            return Ok(response_builder.body(rendered));
                        }
                        custom_token.to_string()
                    }
                    Err(AppError::Validation(msg)) => {
                        let mut response_builder = with_no_cache_headers(HttpResponse::Ok());
                        let csrf_token = get_or_set_csrf_token(&req, &mut response_builder);

                        let mut context = Context::new();
                        context.insert("site_name", "pastry");
                        context.insert("save_paste_url", SAVE_PASTE_URL);
                        context.insert("csrf_token", &csrf_token);
                        context.insert("content", &form.content);
                        context.insert("css", &css);
                        context.insert("custom_token", custom_token);
                        context.insert(
                            "flash_messages",
                            &vec![FlashMessage {
                                level: "error".to_string(),
                                message: msg,
                            }],
                        );

                        try_or_handle!(
                            setup_view_paste_context(&mut context, &data, &jwt_secret, &req, None).await,
                            &data,
                            &jwt_secret,
                            &req
                        );
                        let rendered = try_or_handle!(
                            render_template(&data.tera, TEMPLATE_PASTE_FORM, &context),
                            &data,
                            &jwt_secret,
                            &req
                        );

                        response_builder.content_type("text/html");
                        clear_flash_cookie(&mut response_builder);

                        return Ok(response_builder.body(rendered));
                    }
                    Err(e) => return Err(e),
                }
            } else {
                try_or_handle!(generate_random_token(&pool).await, &data, &jwt_secret, &req)
            }
        } else {
            try_or_handle!(generate_random_token(&pool).await, &data, &jwt_secret, &req)
        };

        try_or_handle!(
            sqlx::query(
                "INSERT INTO pastes (token, content, css, timestamp, edit_timestamp, user_id) VALUES ($1, $2, $3, $4, $5, $6)"
            )
            .bind(&token)
            .bind(&content)
            .bind(&css)
            .bind(Utc::now())
            .bind(Utc::now())
            .bind(&user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        try_or_handle!(
            sqlx::query("INSERT INTO pastes_fts (token, content_tsv)
                VALUES ($1, to_tsvector('english', $2))
                ON CONFLICT (token) DO UPDATE SET content_tsv = EXCLUDED.content_tsv")
                .bind(&token)
                .bind(&content)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);

        Ok(
            append_flash_message(
                HttpResponse::Found()
                    .append_header(("Location", format!("/{}", token))),
                "Paste saved successfully",
                "success",
            )
        )
    }).await
}

// retrieves and displays a paste
pub async fn view_paste(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();

    let cookie_name = format!("viewed_paste_{}", &token);
    let should_increment_views = req.cookie(&cookie_name).is_none();

    if should_increment_views {
        let mut tx = try_or_handle!(data.db_pool.begin().await.map_err(AppError::from), &data, &jwt_secret, &req);

        try_or_handle!(
            sqlx::query("UPDATE pastes SET views = views + 1 WHERE token = $1")
                .bind(&token)
                .execute(&mut *tx)
                .await
                .map_err(AppError::from),
            &data,
            &jwt_secret,
            &req
        );

        try_or_handle!(tx.commit().await.map_err(AppError::from), &data, &jwt_secret, &req);
    }

    let paste_opt = try_or_handle!(get_paste_by_token(&data.db_pool, &token).await, &data, &jwt_secret, &req);
    let paste = match paste_opt {
        Some(p) => p,
        None => return render_404(&data, &jwt_secret, &req).await,
    };

    let row = try_or_handle!(
        sqlx::query("SELECT username FROM users WHERE user_id = $1")
            .bind(&paste.user_id)
            .fetch_one(&data.db_pool)
            .await
            .map_err(AppError::Database),
        &data,
        &jwt_secret,
        &req
    );

    let username = row.try_get::<String, _>("username").unwrap_or_else(|_| "Unknown".to_string());

    let mut context = tera::Context::new();
    context.insert("owner_username", &username);
    context.insert("owner_profile_url", &format!("/profile/{}", &username));
    context.insert("views", &paste.views);
    context.insert("page_title", &paste.page_title);
    context.insert("favicon_url", &paste.favicon_url);
    context.insert("embed_description", &paste.embed_description);
    context.insert("embed_image_url", &paste.embed_image_url);
    context.insert("embed_color", &paste.embed_color);

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);
    context.insert("csrf_token", &csrf_token);

    try_or_handle!(
        setup_view_paste_context(
            &mut context,
            &data,
            &jwt_secret,
            &req,
            Some(&Paste {
                content: get_sanitizer().clean(&paste.content).to_string(),
                ..paste
            }),
        )
        .await,
        &data,
        &jwt_secret,
        &req
    );

    let rendered = try_or_handle!(render_template(&data.tera, TEMPLATE_PASTE_VIEW, &context), &data, &jwt_secret, &req);

    let cookie_path = format!("/{}", &token);
    let viewed_cookie = Cookie::build(cookie_name, "1")
        .http_only(true)
        .secure(true)
        .path(&cookie_path)
        .max_age(Duration::days(7))
        .finish();

    response
        .content_type("text/html")
        .append_header(("Set-Cookie", viewed_cookie.to_string()));

    clear_flash_cookie(&mut response);

    Ok(response.body(rendered))
}

// retrieves the raw CSS for a paste
pub async fn view_raw_css(
    data: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();

    let css = sqlx::query("SELECT css FROM pastes WHERE token = $1")
        .bind(&token)
        .fetch_optional(&data.db_pool)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Paste not found".to_string()))?
        .try_get::<String, _>("css")
        .map_err(AppError::Database)?;

    Ok(HttpResponse::Ok().content_type("text/css").body(css))
}

pub async fn edit_paste_form(
    data: web::Data<AppState>,
    path: web::Path<String>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();
    let pool = &data.db_pool;

    let paste_opt = try_or_handle!(get_paste_by_token(&*pool, &token).await, &data, &jwt_secret, &req);
    let paste = match paste_opt {
        Some(p) => p,
        None => return render_404(&data, &jwt_secret, &req).await,
    };

    let user_id_opt = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);
    let user_id = match user_id_opt {
        Some(id) => id,
        None => return handle_error(AppError::Unauthorized("User not logged in".to_string()), &data, &jwt_secret, &req).await,
    };

    let is_main_owner = try_or_handle!(is_main_owner(&*pool, &token, &user_id).await, &data, &jwt_secret, &req);
    let is_admin = try_or_handle!(is_user_admin(&*pool, &user_id).await, &data, &jwt_secret, &req);
    let is_collaborator = try_or_handle!(is_collaborator(&*pool, &token, &user_id).await, &data, &jwt_secret, &req);
    let can_edit = is_admin || is_main_owner || is_collaborator;

    let rows = try_or_handle!(
        sqlx::query(
            "SELECT u.username FROM paste_collaborators pc JOIN users u ON pc.user_id = u.user_id WHERE pc.paste_token = $1"
        )
        .bind(&token)
        .fetch_all(&*pool)
        .await
        .map_err(AppError::Database),
        &data, &jwt_secret, &req
    );

    let collaborators_usernames_vec: Vec<String> = rows
        .into_iter()
        .map(|row| row.try_get("username").map_err(AppError::Database))
        .collect::<Result<_, _>>()
        .map_err(|e| e)?;

    let collaborators_usernames_str = collaborators_usernames_vec.join(", ");

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = Context::new();
    try_or_handle!(setup_edit_paste_context(&mut context, &data, &jwt_secret, &req, &mut response, &paste).await, &data, &jwt_secret, &req);

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    context.insert("can_edit", &can_edit);
    context.insert("is_main_owner", &is_main_owner);
    context.insert("is_admin", &is_admin);
    context.insert("collaborators_usernames", &collaborators_usernames_str);
    context.insert("csrf_token", &csrf_token);
    context.insert("page_title", &paste.page_title);
    context.insert("favicon_url", &paste.favicon_url);
    context.insert("embed_description", &paste.embed_description);
    context.insert("embed_image_url", &paste.embed_image_url);
    context.insert("embed_color", &paste.embed_color);

    let body = try_or_handle!(render_template(&data.tera, TEMPLATE_EDIT_PASTE, &context), &data, &jwt_secret, &req);

    response
        .content_type("text/html");

    clear_flash_cookie(&mut response);

    Ok(response.body(body))
}

pub async fn edit_paste(
    data: web::Data<AppState>,
    path: web::Path<String>,
    form: web::Form<EditForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let token = path.into_inner();

    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("").to_owned();
    let form_inner = form.into_inner();

    let req_clone = req.clone();

    with_csrf_validation(req_clone.clone(), &form_csrf_token, move || async move {
        let user_id_opt = try_or_handle!(get_user_id_from_jwt(&req, &jwt_secret), &data, &jwt_secret, &req);
        let user_id = match user_id_opt {
            Some(id) => id,
            None => return Err(AppError::Unauthorized("User not logged in".to_string())),
        };

        let (paste, _) = try_or_handle!(validate_and_get_paste(&data, &token, &req, &jwt_secret).await, &data, &jwt_secret, &req);

        let pool = &data.db_pool;

        let is_admin = try_or_handle!(is_user_admin(pool, &user_id).await, &data, &jwt_secret, &req);
        let is_main_owner = try_or_handle!(is_main_owner(pool, &token, &user_id).await, &data, &jwt_secret, &req);
        let is_collaborator = try_or_handle!(is_collaborator(pool, &token, &user_id).await, &data, &jwt_secret, &req);

        if !is_main_owner && !is_collaborator && !is_admin {
            return Err(AppError::Unauthorized(
                "You do not have permission to edit this paste".to_string(),
            ));
        }

        let response = match form_inner.action {
            Some(PasteAction::Save) => {
                try_or_handle!(
                    handle_save_action(
                        &data,
                        &jwt_secret,
                        &token,
                        req_clone,
                        &paste,
                        form_inner,
                        is_main_owner,
                        is_admin,
                    ).await,
                    &data, &jwt_secret, &req
                )
            }
            Some(PasteAction::Delete) => {
                try_or_handle!(handle_delete_action(&data, &token, &user_id).await, &data, &jwt_secret, &req)
            }
            None => HttpResponse::Found()
                .append_header(("Location", format!("{}{}", EDIT_PASTE_URL_PREFIX, token)))
                .finish(),
        };

        Ok(response)
    }).await
}