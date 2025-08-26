use crate::common::constants::{EDIT_PASTE_URL_PREFIX, MAX_PAGE_TITLE_LEN, 
    MAX_FAVICON_URL_LEN, MAX_EMBED_IMAGE_URL_LEN, MAX_EMBED_DESCRIPTION_LEN, DEFAULT_PROFILE_PICTURES};
use crate::common::prelude::*;
use crate::jws::validate_jwt;
use crate::models::{Friend, Paste, TemplateUser, FlashMessage};
use crate::state::AppState;
use actix_web::{HttpResponse, HttpResponseBuilder, HttpRequest};
use actix_web::http::{header, StatusCode};
use actix_web::http::header::{CACHE_CONTROL, PRAGMA, EXPIRES};
use actix_web::cookie::{Cookie, SameSite, time::Duration, time::OffsetDateTime};
use ammonia::{Builder, Url};
use rand::{distributions::Alphanumeric, Rng};
use tera::{Tera, Context};
use sqlx::{Postgres, Row, Executor};
use crate::common::error::AppError;
use rand::seq::SliceRandom; 
use serde_json::json;
use chrono::DateTime;

pub fn get_sanitizer() -> Builder<'static> {
    let mut builder = Builder::default();
    builder
        .add_tags(&[
            "div", "p", "span", "a", "b", "i", "ul", "ol", "li", "strong", "em", "br", "img", "button", "iframe",
            "table", "thead", "tbody", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6",
            "svg", "path", "circle", "rect", "line", "polygon", "polyline", "text", "g", "defs",
            "linearGradient", "radialGradient", "filter", "stop", "use",
            "audio",
            "input", "label",
        ])
        .add_generic_attributes(&[
            "class", "id", "style", "href", "src", "alt", "title", "data", "target", "sandbox",
            //svg attributes
            "width", "height", "viewBox", "xmlns", "fill", "stroke", "stroke-width", "d", "cx",
            "cy", "r", "x", "y", "x1", "y1", "x2", "y2", "points", "transform", "text-anchor",
            "font-family", "font-size", "opacity", "stop-color", "offset", "gradientTransform",
            "gradientUnits", "spreadMethod", "xlink:href",
            "aria-hidden",
            //audio atrributes
            "controls", "loop", "muted", "preload", "autoplay",
            //input attributes
            "type", "name", "value", "placeholder", "disabled", "readonly", "checked", "min", "max", "step",
            "size", "maxlength", "pattern", "required", "autofocus", "list", "autocomplete",
        ])
        .add_url_schemes(&["http", "https", "mailto"]);
    builder
}

// logging macro
#[macro_export]
macro_rules! log_and_error {
    ($err:expr, $fmt:expr $(, $args:expr)* $(,)?) => {{
        log::error!(concat!($fmt, ": {:?}"), $($args,)* $err);
        actix_web::error::ErrorInternalServerError(format!(concat!($fmt, ": {:?}"), $($args,)* $err))
    }};
}

// CSRF token
pub fn generate_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub fn set_csrf_token() -> (String, Cookie<'static>) {
    let token = generate_csrf_token();
    let cookie = Cookie::build("csrf_token", token.clone())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::hours(12))
        .finish();
    (token, cookie)
}

pub fn get_or_set_csrf_token(req: &HttpRequest, resp: &mut HttpResponseBuilder) -> String {
    if let Some(cookie) = req.cookie("csrf_token") {
        cookie.value().to_string()
    } else {
        let token = crate::common::utils::generate_csrf_token();
        let cookie = Cookie::build("csrf_token", token.clone())
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
            .path("/")
            .max_age(Duration::hours(12))
            .finish();
        resp.append_header(("Set-Cookie", cookie.to_string()));
        token
    }
}

pub fn validate_csrf_token(req: &HttpRequest, form_csrf_token: &str) -> Result<bool, actix_web::Error> {
    let cookie_token = req.cookie("csrf_token").map(|c| c.value().to_string());
    match cookie_token {
        Some(stored) => {
            if stored != form_csrf_token {
                log::warn!(
                    "CSRF token mismatch: provided={}, expected={}",
                    form_csrf_token,
                    stored
                );
                return Ok(false);
            }
            Ok(true)
        }
        None => {
            log::warn!("No CSRF token found in cookie for request to {}", req.path());
            Ok(false)
        }
    }
}

pub async fn with_csrf_validation<T, F, Fut>(
    req: HttpRequest,
    form_csrf_token: &str,
    handler: F,
) -> Result<T, AppError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, AppError>>,
{
    if !validate_csrf_token(&req, form_csrf_token)? {
        return Err(AppError::BadRequest("Invalid CSRF token".to_string()));
    }
    handler().await
}

pub fn with_no_cache_headers(mut builder: HttpResponseBuilder) -> HttpResponseBuilder {
    builder
        .insert_header((CACHE_CONTROL, "no-store, no-cache, must-revalidate, proxy-revalidate"))
        .insert_header((PRAGMA, "no-cache"))
        .insert_header((EXPIRES, "0"));
    builder
}

// rendering
pub fn render_template(
    tera: &Tera,
    template_name: &str,
    context: &tera::Context,
) -> Result<String, AppError> {
    tera.render(template_name, context).map_err(|e| {
        log::error!("Template rendering error for {}: {:?}", template_name, e);
        AppError::Template(e)
    })
}

pub async fn render_error_page(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
    status: StatusCode,
    template: &str,
    error_message: &str,
) -> Result<HttpResponse, AppError> {
    let mut context = Context::new();
    setup_user_context(&mut context, data, req, jwt_secret).await?;
    context.insert("site_name", "pastry");
    context.insert("error", error_message);

    let mut response_builder = HttpResponse::build(status);

    let csrf_token = get_or_set_csrf_token(req, &mut response_builder);
    context.insert("csrf_token", &csrf_token);

    let rendered = render_template(&data.tera, template, &context)?;

    let response = response_builder
        .content_type("text/html")
        .body(rendered);

    Ok(response)
}

pub async fn render_404(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    render_error_page(
        data,
        jwt_secret,
        req,
        StatusCode::NOT_FOUND,
        "404.html",
        "Page or paste not found",
    )
    .await
}

pub async fn render_403(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    render_error_page(
        data,
        jwt_secret,
        req,
        StatusCode::FORBIDDEN,
        "403.html",
        "Forbidden: You don't have permission to access this resource",
    )
    .await
}

pub async fn render_500(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    render_error_page(
        data,
        jwt_secret,
        req,
        StatusCode::INTERNAL_SERVER_ERROR,
        "500.html",
        "Internal Server Error: Something went wrong",
    )
    .await
}

pub async fn render_400(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
    error_message: &str,
) -> Result<HttpResponse, AppError> {
    render_error_page(
        data,
        jwt_secret,
        req,
        StatusCode::BAD_REQUEST,
        "400.html",
        error_message,
    )
    .await
}

// error handling

pub async fn handle_error(
    err: AppError,
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
) -> Result<HttpResponse, AppError> {
    match err {
        AppError::NotFound(_) => render_404(data, jwt_secret, req).await,
        AppError::Forbidden(_) => render_403(data, jwt_secret, req).await,
        AppError::BadRequest(msg) => render_400(data, jwt_secret, req, &msg).await,
        AppError::Unauthorized(_) => render_403(data, jwt_secret, req).await,
        AppError::Database(_) => render_500(data, jwt_secret, req).await,
        AppError::Template(_) => todo!(),
        AppError::Validation(_) => todo!(),
        AppError::Internal(_) => todo!(),
    }
}

pub async fn handle_api_error(err: AppError) -> Result<HttpResponse, AppError> {
    let (status, message) = match err {
        AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
        AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        AppError::Database(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error".to_string(),
        ),
        AppError::Template(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Template rendering error".to_string(),
        ),
        AppError::Validation(msg) => (
            StatusCode::BAD_REQUEST,
            msg,
        ),
        AppError::Internal(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            msg,
        ),
    };

    Ok(HttpResponse::build(status)
        .content_type("application/json")
        .json(json!({ "error": message })))
}

#[macro_export]
macro_rules! try_or_handle {
    ( $expr:expr, $data:expr, $jwt_secret:expr, $req:expr ) => {
        match $expr {
            Ok(val) => val,
            Err(e) => {
                return crate::common::utils::handle_error(e, $data, $jwt_secret, $req).await;
            }
        }
    };
}

// context setup
pub async fn setup_view_paste_context(
    context: &mut tera::Context,
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
    paste: Option<&Paste>,
) -> Result<(), AppError> {
    setup_user_context(context, data, req, jwt_secret).await?;
    if let Some(paste) = paste {
        context.insert("paste", paste);
        context.insert(
            "timestamp",
            &paste.timestamp.format("%d %b %Y %H:%M UTC").to_string(),
        );
        context.insert(
            "edit_timestamp",
            &paste.edit_timestamp.format("%d %b %Y %H:%M UTC").to_string(),
        );
        context.insert(
            "edit_paste_url",
            &format!("{}{}", EDIT_PASTE_URL_PREFIX, paste.token),
        );
    }
    Ok(())
}

pub async fn setup_edit_paste_context(
    context: &mut tera::Context,
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: &HttpRequest,
    resp: &mut HttpResponseBuilder,
    paste: &Paste,
) -> Result<(), AppError> {
    setup_user_context(context, data, req, jwt_secret).await?;
    context.insert("paste", paste);
    context.insert("css", &paste.css);
    context.insert("can_edit", &true);
    context.insert(
        "edit_paste_url",
        &format!("{}{}", EDIT_PASTE_URL_PREFIX, paste.token),
    );

    let csrf_token = get_or_set_csrf_token(req, resp);
    context.insert("csrf_token", &csrf_token);

    Ok(())
}

pub async fn setup_user_context(
    context: &mut Context,
    data: &web::Data<AppState>,
    req: &HttpRequest,
    jwt_secret: &web::Data<String>,
) -> Result<(), AppError> {
    context.insert("paste_form_url", "/");
    context.insert("info_url", "/info");
    context.insert("dashboard_url", "/dashboard");
    context.insert("admin_url", "/admin/panel"); 
    context.insert("login_url", "/login");
    context.insert("logout_url", "/logout");
    context.insert("register_url", "/register");

    if let Some(cookie) = req.cookie("jwt_token") {
        let token = cookie.value();
        match validate_jwt(token, jwt_secret.as_ref()) {
            Ok(claims) => {
                let banned = is_user_banned(&data.db_pool, &claims.sub).await.unwrap_or(false);
                if banned {
                    context.insert("is_logged_in", &false);
                    context.insert("is_admin", &false);
                    return Err(AppError::Unauthorized("User is banned".to_string()));
                }

                if let Some(user) = get_template_user_from_jwt(data, jwt_secret, Some(req)).await? {
                    context.insert("current_user", &user);
                    context.insert("user_profile_url", &format!("/profile/{}", user.username));
                    context.insert("is_logged_in", &true);

                    let is_admin = is_user_admin(&data.db_pool, &claims.sub).await.unwrap_or(false);
                    context.insert("is_admin", &is_admin);
                } else {
                    context.insert("is_logged_in", &false);
                    context.insert("is_admin", &false);
                }
            }
            Err(_) => {
                context.insert("is_logged_in", &false);
                context.insert("is_admin", &false);
            }
        }
    } else {
        context.insert("is_logged_in", &false);
        context.insert("is_admin", &false);
    }

    Ok(())
}

pub async fn get_template_user_from_jwt(
    data: &web::Data<AppState>,
    jwt_secret: &web::Data<String>,
    req: Option<&HttpRequest>,
) -> Result<Option<TemplateUser>, AppError> {
    let user_id = match req {
        Some(req) => get_user_id_from_jwt(req, jwt_secret)?,
        None => return Ok(None),
    };

    if let Some(user_id) = user_id {
        let row = sqlx::query("SELECT username, profile_picture_url FROM users WHERE user_id = $1")
            .bind(&user_id)
            .fetch_optional(&data.db_pool)
            .await
            .map_err(AppError::Database)?;

        if let Some(row) = row {
            return Ok(Some(TemplateUser {
                username: row.try_get("username").map_err(AppError::Database)?,
                profile_picture_url: row.try_get("profile_picture_url").map_err(AppError::Database)?,
            }));
        }
    }
    Ok(None)
}

// user getters
pub async fn user_exists<'e, E>(executor: E, username: &str) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query("SELECT 1 FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(executor)
        .await
        .map_err(AppError::Database)?;

    Ok(row.is_some())
}

pub async fn get_user_id<'e, E>(executor: E, username: &str) -> Result<Option<String>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query("SELECT user_id FROM users WHERE username = $1")
        .bind(username)
        .fetch_optional(executor)
        .await
        .map_err(AppError::Database)?;

    if let Some(row) = row {
        let user_id: String = row.try_get("user_id").map_err(AppError::Database)?;
        Ok(Some(user_id))
    } else {
        Ok(None)
    }
}

pub fn get_user_id_from_jwt(
    req: &HttpRequest,
    jwt_secret: &web::Data<String>,
) -> Result<Option<String>, AppError> {
    if let Some(cookie) = req.cookie("jwt_token") {
        let token = cookie.value();
        let claims = validate_jwt(token, jwt_secret)?;
        Ok(Some(claims.sub))
    } else {
        Ok(None)
    }
}

pub async fn assign_random_default_picture<'e, E>(
    executor: E,
    user_id: &str,
) -> Result<String, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let mut rng = rand::thread_rng();
    let picture_url = DEFAULT_PROFILE_PICTURES.choose(&mut rng).unwrap().to_string();

    sqlx::query("UPDATE users SET profile_picture_url = $1 WHERE user_id = $2")
        .bind(&picture_url)
        .bind(user_id)
        .execute(executor)
        .await
        .map_err(AppError::Database)?;

    Ok(picture_url)
}

pub async fn get_user_profile<'e, E>(
    executor: E,
    username: &str,
) -> Result<Option<(String, String, Option<String>, Option<String>, Option<String>)>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT user_id, username, display_name, bio, profile_picture_url FROM users WHERE username = $1"
    )
    .bind(username)
    .fetch_optional(executor)
    .await
    .map_err(AppError::Database)?;

    if let Some(row) = row {
        let profile = (
            row.try_get::<String, _>("user_id").map_err(AppError::Database)?,
            row.try_get::<String, _>("username").map_err(AppError::Database)?,
            row.try_get::<Option<String>, _>("display_name").map_err(AppError::Database)?,
            row.try_get::<Option<String>, _>("bio").map_err(AppError::Database)?,
            row.try_get::<Option<String>, _>("profile_picture_url").map_err(AppError::Database)?,
        );
        Ok(Some(profile))
    } else {
        Ok(None)
    }
}

pub async fn is_user_admin<'e, E>(
    executor: E,
    user_id: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query("SELECT role FROM users WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(executor)
        .await
        .map_err(AppError::Database)?;

    let role: String = row.try_get("role").map_err(AppError::Database)?;
    Ok(role.eq_ignore_ascii_case("admin"))
}

pub async fn is_user_banned<'e, E>(
    executor: E,
    user_id: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query("SELECT banned FROM users WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(executor)
        .await
        .map_err(AppError::Database)?;

    let banned: bool = row.try_get("banned").map_err(AppError::Database)?;
    Ok(banned)
}

pub fn validate_username(username: &str) -> HashMap<String, Vec<String>> {
    let mut errors: HashMap<String, Vec<String>> = HashMap::new();

    if username.is_empty() {
        errors.entry("username".to_string())
            .or_default()
            .push("Username cannot be empty".to_string());
    } else if username.len() < 3 || username.len() > 20 {
        errors.entry("username".to_string())
            .or_default()
            .push("Username must be between 3 and 20 characters".to_string());
    } else if !username.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        errors.entry("username".to_string())
            .or_default()
            .push("Username can only contain lowercase letters, numbers, or underscores".to_string());
    }

    errors
}

// friends
pub async fn get_friends<'e, E>(
    executor: E,
    user_id: &str,
    limit: u32,
    offset: u32,
) -> Result<Vec<Friend>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query(
        r#"
        SELECT u.username, u.profile_picture_url
        FROM users u
        JOIN friendships f ON (u.user_id = f.user_id1 OR u.user_id = f.user_id2)
        WHERE (f.user_id1 = $1 OR f.user_id2 = $2) AND u.user_id != $3
        LIMIT $4 OFFSET $5
        "#
    )
    .bind(user_id)
    .bind(user_id)
    .bind(user_id)
    .bind(limit as i64)
    .bind(offset as i64)
    .fetch_all(executor)
    .await
    .map_err(AppError::Database)?;

    let friends = rows.into_iter()
        .map(|row| {
            Ok(Friend {
                username: row.try_get("username").map_err(AppError::Database)?,
                profile_picture_url: row.try_get("profile_picture_url").map_err(AppError::Database)?,
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;

    Ok(friends)
}

pub async fn are_friends<'e, E>(
    executor: E,
    user_id1: &str,
    user_id2: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        r#"
        SELECT 1 
        FROM friendships 
        WHERE (user_id1 = $1 AND user_id2 = $2) OR (user_id1 = $3 AND user_id2 = $4)
        "#
    )
    .bind(user_id1)
    .bind(user_id2)
    .bind(user_id2)
    .bind(user_id1)
    .fetch_optional(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(row.is_some())
}

pub async fn add_friendship<'e, E>(
    executor: E,
    user_id1: &str,
    user_id2: &str,
) -> Result<(), AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (uid1, uid2) = if user_id1 < user_id2 {
        (user_id1, user_id2)
    } else {
        (user_id2, user_id1)
    };

    sqlx::query(
        "INSERT INTO friendships (user_id1, user_id2) VALUES ($1, $2)"
    )
    .bind(uid1)
    .bind(uid2)
    .execute(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(())
}

pub async fn remove_friendship<'e, E>(
    executor: E,
    user_id1: &str,
    user_id2: &str,
) -> Result<bool, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (uid1, uid2) = if user_id1 < user_id2 {
        (user_id1, user_id2)
    } else {
        (user_id2, user_id1)
    };

    let result = sqlx::query(
        "DELETE FROM friendships WHERE user_id1 = $1 AND user_id2 = $2"
    )
    .bind(uid1)
    .bind(uid2)
    .execute(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(result.rows_affected() > 0)
}

// paste specific
pub async fn get_paste_by_token<'e, E>(
    executor: E,
    token: &str,
) -> Result<Option<Paste>, AppError>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(
        "SELECT token, content, css, timestamp, edit_timestamp, user_id, views, 
        page_title, favicon_url, embed_description, embed_image_url, embed_color 
        FROM pastes WHERE token = $1"
    )
    .bind(token)
    .fetch_optional(executor)
    .await
    .map_err(AppError::Database)?;

    if let Some(row) = row {
        let paste = Paste {
            token: row.try_get("token").map_err(AppError::Database)?,
            content: row.try_get("content").map_err(AppError::Database)?,
            css: row.try_get("css").map_err(AppError::Database)?,
            timestamp: row
                .try_get::<DateTime<Utc>, _>("timestamp")
                .unwrap_or_else(|_| Utc::now()),
            edit_timestamp: row
                .try_get::<DateTime<Utc>, _>("edit_timestamp")
                .unwrap_or_else(|_| Utc::now()),
            user_id: row.try_get("user_id").map_err(AppError::Database)?,
            views: row.try_get("views").map_err(AppError::Database)?,
            page_title: row.try_get("page_title").map_err(AppError::Database)?,
            favicon_url: row.try_get("favicon_url").map_err(AppError::Database)?,
            embed_description: row.try_get("embed_description").map_err(AppError::Database)?,
            embed_image_url: row.try_get("embed_image_url").map_err(AppError::Database)?,
            embed_color: row.try_get("embed_color").map_err(AppError::Database)?,
        };
        Ok(Some(paste))
    } else {
        Ok(None)
    }
}

pub fn validate_paste_content(content: &str, css: Option<&str>) -> Result<(), AppError> {
    if content.trim().is_empty() {
        return Err(AppError::Validation(
            "Paste content cannot be empty".to_string(),
        ));
    }
    if content.len() > crate::common::constants::MAX_PASTE_CONTENT_SIZE {
        return Err(AppError::Validation(
            "Paste content too large (max 1MB)".to_string(),
        ));
    }
    if let Some(css) = css {
        if css.len() > crate::common::constants::MAX_CSS_SIZE {
            return Err(AppError::Validation(
                "CSS content too large (max 100KB)".to_string(),
            ));
        }
    }
    Ok(())
}


pub fn validate_meta_inputs(
    page_title: &Option<String>,
    favicon_url: &Option<String>,
    embed_description: &Option<String>,
    embed_image_url: &Option<String>,
    embed_color: &Option<String>,
) -> Result<(), AppError> {
    if let Some(title) = page_title {
        if title.len() > MAX_PAGE_TITLE_LEN {
            return Err(AppError::Validation(format!(
                "Page title is too long (max {} characters)",
                MAX_PAGE_TITLE_LEN
            )));
        }
    }
    if let Some(favicon) = favicon_url {
        if favicon.len() > MAX_FAVICON_URL_LEN {
            return Err(AppError::Validation(format!(
                "Favicon URL is too long (max {} characters)",
                MAX_FAVICON_URL_LEN
            )));
        }
        if !favicon.is_empty() && Url::parse(favicon).is_err() {
            return Err(AppError::Validation("Favicon URL is not valid".to_string()));
        }
    }
    if let Some(desc) = embed_description {
        if desc.len() > MAX_EMBED_DESCRIPTION_LEN {
            return Err(AppError::Validation(format!(
                "Embed description is too long (max {} characters)",
                MAX_EMBED_DESCRIPTION_LEN
            )));
        }
    }
    if let Some(embed_image) = embed_image_url {
        if embed_image.len() > MAX_EMBED_IMAGE_URL_LEN {
            return Err(AppError::Validation(format!(
                "Embed image URL is too long (max {} characters)",
                MAX_EMBED_IMAGE_URL_LEN
            )));
        }
        if !embed_image.is_empty() && Url::parse(embed_image).is_err() {
            return Err(AppError::Validation("Embed image URL is not valid".to_string()));
        }
    }
    if let Some(color) = embed_color {
        if !color.is_empty() {
            if !color.starts_with('#') || color.len() != 7 || !color[1..].chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(AppError::Validation("Embed color must be a valid hex color (e.g., #FF0000)".to_string()));
            }
        }
    }
    Ok(())
}

// dashboard
#[derive(Debug, serde::Serialize)]
pub struct Pagination {
    pub total_pages: usize,
    pub has_next: bool,
    pub has_prev: bool,
}

pub fn calculate_pagination(total_count: usize, page: usize, per_page: usize) -> Pagination {
    if per_page == 0 {
        return Pagination {
            total_pages: 1,
            has_next: false,
            has_prev: false,
        };
    }

    let total_pages = ((total_count as f64) / (per_page as f64)).ceil() as usize;
    let total_pages = total_pages.max(1);
    let page = page.max(1).min(total_pages);
    let has_next = page < total_pages;
    let has_prev = page > 1;

    Pagination {
        total_pages,
        has_next,
        has_prev,
    }
}

// flash messages

pub fn append_flash_message(
    response: &mut HttpResponseBuilder,
    message: &str,
    flash_type: &str,
) -> HttpResponse {
    let flash_cookie = Cookie::build("flash", format!("{}:{}", flash_type, message))
        .path("/")
        .http_only(true)
        .finish();

    response.append_header((
        header::SET_COOKIE,
        flash_cookie.to_string(),
    ));

    response.finish()
}

pub fn extract_flash_message(req: &HttpRequest) -> Option<FlashMessage> {
    if let Some(cookie) = req.cookie("flash") {
        let value = cookie.value();
        if let Some(split_pos) = value.find(':') {
            let level = &value[..split_pos];
            let message = &value[split_pos + 1..];
            return Some(FlashMessage {
                level: level.to_string(),
                message: message.to_string(),
            });
        } else {
            log::warn!("Invalid flash cookie format: {}", value);
        }
    }
    None
}

pub fn clear_flash_cookie(resp: &mut HttpResponseBuilder) {
    let cookie = Cookie::build("flash", "")
        .path("/")
        .http_only(true)
        .max_age(Duration::seconds(0))
        .expires(OffsetDateTime::now_utc() - Duration::days(1))
        .finish();
    resp.append_header((header::SET_COOKIE, cookie.to_string()));
}