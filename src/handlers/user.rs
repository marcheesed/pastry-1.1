use crate::common::prelude::*;
use crate::common::utils::{
    render_template, set_csrf_token, append_flash_message, setup_user_context, validate_username,
    with_csrf_validation, is_user_banned, extract_flash_message, clear_flash_cookie,
    get_user_id_from_jwt, with_no_cache_headers, get_or_set_csrf_token,
};
use crate::jws::generate_jwt;
use actix_web::cookie::{time::Duration as ActixDuration, Cookie};
use actix_web::HttpResponseBuilder;
use crate::models::{LoginForm, RegisterForm, FlashMessage};
use bcrypt::{hash, verify, DEFAULT_COST};
use rand::rngs::OsRng;
use rand::{distributions::Alphanumeric, Rng};
use crate::try_or_handle;
use uuid::Uuid;
use sqlx::Row;
use chrono::{Utc, DateTime, Duration};

pub async fn register_user_in_db(
    data: &web::Data<AppState>,
    username: &str,
) -> Result<(String, String), AppError> {
    let pool = &data.db_pool;

    let mut tx = pool.begin().await.map_err(AppError::Database)?;

    let count: i64 = sqlx::query("SELECT COUNT(*) as count FROM users WHERE username = $1")
        .bind(username)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .try_get("count")
        .map_err(AppError::Database)?;

    if count > 0 {
        return Err(AppError::Validation("Username already taken".to_string()));
    }

    let user_id = Uuid::new_v4().to_string();

    let user_token: String = OsRng
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let user_token_hash = hash(&user_token, DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Hashing error: {}", e)))?;

    sqlx::query(
        "INSERT INTO users (user_id, username, user_token_hash, username_last_changed, role, profile_picture_url) VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(&user_id)
    .bind(username)
    .bind(&user_token_hash)
    .bind(Utc::now())
    .bind("user")
    .bind("") 
    .execute(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    let profile_picture_url = crate::common::utils::assign_random_default_picture(&mut *tx, &user_id)
    .await
    .map_err(|e| {
        log::error!("Failed to assign default profile picture for user_id={}: {:?}", user_id, e);
        e 
    })?;

    tx.commit().await.map_err(AppError::Database)?;

    log::info!(
        "User registered: user_id={}, username={}, profile_picture_url={}",
        user_id,
        username,
        profile_picture_url
    );

    Ok((user_id, user_token))
}

pub async fn render_register_form(
    data: &web::Data<AppState>,
    req: &HttpRequest,
    response: &mut HttpResponseBuilder,
    username: &str,
    errors: &HashMap<String, Vec<String>>,
    jwt_secret: &web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let csrf_token = get_or_set_csrf_token(req, response);

    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("register_url", "/register");
    context.insert("csrf_token", &csrf_token);

    setup_user_context(&mut context, &data, &req, &jwt_secret).await?;

    context.insert("username", username);
    context.insert("errors", errors);

    let rendered = render_template(&data.tera, "user/register.html", &context)?;

    Ok(response.content_type("text/html").body(rendered))
}

pub async fn register_form(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let mut response = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("register_url", "/register");
    context.insert("csrf_token", &csrf_token);

    let flash_messages: Vec<FlashMessage> = extract_flash_message(&req).map_or_else(Vec::new, |f| vec![f]);
    context.insert("flash_messages", &flash_messages);

    setup_user_context(&mut context, &data, &req, &jwt_secret).await?;

    context.insert("username", "");
    context.insert("errors", &HashMap::<String, Vec<String>>::new());

    let rendered = render_template(&data.tera, "user/register.html", &context)?;

    if !flash_messages.is_empty() {
        clear_flash_cookie(&mut response);
    }

    Ok(response.content_type("text/html").body(rendered))
}

pub async fn register(
    data: web::Data<AppState>,
    form: web::Form<RegisterForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let username = form.username.trim().to_string();

        let errors = validate_username(&username);
        if !errors.is_empty() {
            let mut response = with_no_cache_headers(HttpResponse::Ok());
            return render_register_form(&data, &req, &mut response, &username, &errors, &jwt_secret).await;
        }

        let (user_id, user_token) = match register_user_in_db(&data, &username).await {
            Ok(result) => result,
            Err(AppError::Validation(msg)) => {
                let mut errors: HashMap<String, Vec<String>> = HashMap::new();
                errors.entry("username".to_string()).or_default().push(msg);
                let mut response = with_no_cache_headers(HttpResponse::Ok());
                return render_register_form(&data, &req, &mut response, &username, &errors, &jwt_secret).await;
            }
            Err(e) => {
                return try_or_handle!(Err(e), &data, &jwt_secret, &req);
            }
        };

        let token = try_or_handle!(
            generate_jwt(&user_id, &username, &jwt_secret),
            &data,
            &jwt_secret,
            &req
        );

        let cookie = Cookie::build("jwt_token", token)
            .path("/")
            .secure(true)
            .http_only(true)
            .max_age(ActixDuration::days(30))
            .finish();

        Ok(append_flash_message(
            HttpResponse::Found()
                .append_header(("Location", format!("/welcome?user_token={}", urlencoding::encode(&user_token))))
                .cookie(cookie),
            "Registration successful. Please save your user token safely!",
            "success",
        ))
    })
    .await
}

pub async fn register_success(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let query = web::Query::<HashMap<String, String>>::from_query(req.query_string())
        .ok()
        .and_then(|q| q.get("user_token").cloned());

    let user_token = match query {
        Some(token) => token,
        None => {
            return Ok(HttpResponse::Found()
                .append_header(("Location", "/register"))
                .finish());
        }
    };

    let mut response = HttpResponse::Ok();

    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("user_token", &user_token);
    context.insert("csrf_token", &csrf_token);
    setup_user_context(&mut context, &data, &req, &jwt_secret).await?;

    let rendered = render_template(&data.tera, "user/register_success.html", &context)?;

    Ok(response
        .content_type("text/html")
        .body(rendered))
}

pub async fn render_login_form(
    data: &web::Data<AppState>,
    req: &HttpRequest,
    username: &str,
    errors: &HashMap<String, Vec<String>>,
    jwt_secret: &web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let mut response = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(req, &mut response);

    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("login_url", "/login");
    context.insert("csrf_token", &csrf_token);

    let flash_messages: Vec<FlashMessage> = extract_flash_message(req)
        .map_or_else(Vec::new, |f| vec![f]);
    context.insert("flash_messages", &flash_messages);

    setup_user_context(&mut context, data, req, jwt_secret).await?;

    context.insert("username", username);
    context.insert("errors", errors);

    let rendered = render_template(&data.tera, "user/login.html", &context)?;

    if !flash_messages.is_empty() {
        clear_flash_cookie(&mut response);
    }

    Ok(response.content_type("text/html").body(rendered))
}

pub async fn login_form(
    data: web::Data<AppState>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let mut response = with_no_cache_headers(HttpResponse::Ok());

    let csrf_token = get_or_set_csrf_token(&req, &mut response);

    let mut context = Context::new();
    context.insert("site_name", "pastry");
    context.insert("login_url", "/login");
    context.insert("csrf_token", &csrf_token);

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    setup_user_context(&mut context, &data, &req, &jwt_secret).await?;

    let rendered = render_template(&data.tera, "user/login.html", &context)?;

    if !flash_messages.is_empty() {
        clear_flash_cookie(&mut response);
    }

    Ok(response.content_type("text/html").body(rendered))
}

pub async fn login(
    data: web::Data<AppState>,
    form: web::Form<LoginForm>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.csrf_token.as_deref().unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let username = form.username.trim();
        let user_token = form.user_token.trim();

        let mut errors: HashMap<String, Vec<String>> = HashMap::new();

        if username.is_empty() || user_token.is_empty() {
            errors.entry("form".to_string())
                .or_default()
                .push("Username and user token cannot be empty".to_string());
            return render_login_form(&data, &req, username, &errors, &jwt_secret).await;
        }

        let row = sqlx::query("SELECT user_token_hash, user_id FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(&data.db_pool)
            .await
            .map_err(AppError::Database)?;

        let (user_token_hash, user_id) = match row {
            Some(row) => {
                let hash: String = row.try_get("user_token_hash").map_err(AppError::Database)?;
                let id: String = row.try_get("user_id").map_err(AppError::Database)?;
                (hash, id)
            }
            None => {
                errors.entry("form".to_string())
                    .or_default()
                    .push("Invalid username or token".to_string());
                return render_login_form(&data, &req, username, &errors, &jwt_secret).await;
            }
        };

        if !verify(user_token, &user_token_hash)
            .map_err(|e| AppError::Internal(format!("Verification error: {}", e)))?
        {
            errors.entry("form".to_string())
                .or_default()
                .push("Invalid username or token".to_string());
            return render_login_form(&data, &req, username, &errors, &jwt_secret).await;
        }

        let is_banned = is_user_banned(&data.db_pool, &user_id).await?;

        if is_banned {
            errors.entry("form".to_string())
                .or_default()
                .push("Your account is banned.".to_string());
            return render_login_form(&data, &req, username, &errors, &jwt_secret).await;
        }

        let token = generate_jwt(&user_id, username, &jwt_secret)?;
        let cookie = Cookie::build("jwt_token", token)
            .path("/")
            .secure(true)
            .http_only(true)
            .max_age(ActixDuration::days(30))
            .finish();

        let mut response_builder = HttpResponse::Found();
        response_builder
            .append_header(("Location", "/"))
            .cookie(cookie);
        Ok(append_flash_message(&mut response_builder, "Login successful", "success"))
    })
    .await
}

pub async fn logout(_: HttpRequest) -> Result<HttpResponse, AppError> {
    let cookie = Cookie::build("jwt_token", "")
        .path("/")
        .secure(true)
        .http_only(true)
        .max_age(ActixDuration::seconds(0))
        .finish();
    Ok(append_flash_message(
        HttpResponse::Found()
            .append_header(("Location", "/"))
            .cookie(cookie),
        "Logged out successfully",
        "success",
    ))
}

pub async fn refresh_user_token(
    data: web::Data<AppState>,
    req: HttpRequest,
    form: web::Form<std::collections::HashMap<String, String>>,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let form_csrf_token = form.get("csrf_token").map(|s| s.as_str()).unwrap_or("");

    with_csrf_validation(req.clone(), form_csrf_token, || async {
        let current_user_id = get_user_id_from_jwt(&req, &jwt_secret)?
            .ok_or_else(|| AppError::Unauthorized("Not logged in".to_string()))?;

        let row = sqlx::query("SELECT user_token_last_refreshed FROM users WHERE user_id = $1")
            .bind(&current_user_id)
            .fetch_one(&data.db_pool)
            .await
            .map_err(AppError::Database)?;

        let last_refreshed: Option<DateTime<Utc>> = row.try_get("user_token_last_refreshed").ok();

        let now = Utc::now();
        let cooldown = Duration::hours(24);

        if let Some(last) = last_refreshed {
            if now - last < cooldown {
                return Err(AppError::Forbidden("You can refresh your token only once every 24 hours".to_string()));
            }
        }

        let new_token: String = OsRng.sample_iter(&Alphanumeric).take(32).map(char::from).collect();

        let new_token_hash = hash(&new_token, DEFAULT_COST)
            .map_err(|e| AppError::Internal(format!("Failed to hash token: {}", e)))?;

        sqlx::query(
            "UPDATE users SET user_token_hash = $1, user_token_last_refreshed = $2 WHERE user_id = $3"
        )
        .bind(&new_token_hash)
        .bind(now)
        .bind(&current_user_id)
        .execute(&data.db_pool)
        .await
        .map_err(AppError::Database)?;

        let (csrf_token, csrf_cookie) = set_csrf_token();
        let mut context = Context::new();
        context.insert("new_user_token", &new_token);
        context.insert("csrf_token", &csrf_token);
        setup_user_context(&mut context, &data, &req, &jwt_secret).await?;

        let rendered = render_template(&data.tera, "user/refresh_token_success.html", &context)?;

        let mut response = HttpResponse::Ok();
        response.content_type("text/html");
        response.append_header(("Set-Cookie", csrf_cookie.to_string()));

        Ok(response.body(rendered))
    })
    .await
}