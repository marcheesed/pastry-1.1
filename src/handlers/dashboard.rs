use crate::common::constants::{
    BASE_COUNT_SQL, BASE_PASTES_SQL, PASTES_PER_PAGE, SEARCH_COUNT_SQL, SEARCH_PASTES_SQL,
};
use crate::common::prelude::*;
use crate::common::utils::{
    calculate_pagination, get_user_id_from_jwt, render_template, setup_user_context,
    Pagination, extract_flash_message, clear_flash_cookie, with_no_cache_headers, get_or_set_csrf_token,
};
use crate::try_or_handle;
use sqlx::{PgPool, Row};
use sqlx::types::chrono::{DateTime, Utc};
use crate::models::{DashboardQuery, Paste, FlashMessage};

#[derive(Debug)]
struct PasteResult {
    pastes: Vec<Paste>,
    page: usize,
    total_count: usize,
    pagination: Pagination,
}

#[derive(Debug)]
enum SortOption {
    TokenAsc,
    TimestampDesc,
    EditTimestampDesc,
}

impl SortOption {
    fn to_sql(&self) -> &'static str {
        match self {
            SortOption::TokenAsc => "token ASC",
            SortOption::TimestampDesc => "timestamp DESC",
            SortOption::EditTimestampDesc => "edit_timestamp DESC",
        }
    }
}

async fn fetch_user_pastes(
    pool: &PgPool,
    user_id: &str,
    query: &DashboardQuery,
) -> Result<PasteResult, AppError> {
    let (count_sql, pastes_sql, search_pattern) = if let Some(ref search_term) = query.search {
        (
            SEARCH_COUNT_SQL,
            SEARCH_PASTES_SQL,
            Some(format!("%{}%", search_term)),
        )
    } else {
        (BASE_COUNT_SQL, BASE_PASTES_SQL, None)
    };

    let total_count: (i64,) = if let Some(pattern) = &search_pattern {
        sqlx::query_as(count_sql)
            .bind(user_id)
            .bind(pattern)
            .fetch_one(pool)
            .await?
    } else {
        sqlx::query_as(count_sql)
            .bind(user_id)
            .fetch_one(pool)
            .await?
    };
    let total_count = total_count.0 as usize;

    let page = query.page.unwrap_or(1);
    let pagination = calculate_pagination(total_count, page, PASTES_PER_PAGE);
    let page = page.max(1).min(pagination.total_pages);
    let offset = (page - 1) * PASTES_PER_PAGE;

    let mut sql = pastes_sql.to_string();

    let order_by = match query.sort.as_deref() {
        Some("a-z") => SortOption::TokenAsc,
        Some("created") => SortOption::TimestampDesc,
        Some("edited") => SortOption::EditTimestampDesc,
        _ => SortOption::TimestampDesc,
    }
    .to_sql();

    if search_pattern.is_some() {
        sql.push_str(&format!(" ORDER BY {} LIMIT $3 OFFSET $4", order_by));
    } else {
        sql.push_str(&format!(" ORDER BY {} LIMIT $2 OFFSET $3", order_by));
    }

    let mut query_builder = sqlx::query(&sql);

    query_builder = query_builder.bind(user_id);

    if let Some(pattern) = &search_pattern {
        query_builder = query_builder.bind(pattern);
        query_builder = query_builder.bind(PASTES_PER_PAGE as i64);
        query_builder = query_builder.bind(offset as i64);
    } else {
        query_builder = query_builder.bind(PASTES_PER_PAGE as i64);
        query_builder = query_builder.bind(offset as i64);
    }

    let rows = query_builder.fetch_all(pool).await?;

    let pastes = rows
        .into_iter()
        .map(|row| Paste {
            token: row.try_get(0).unwrap_or_default(),
            content: row.try_get(1).unwrap_or_default(),
            css: row.try_get(2).unwrap_or_default(),
            timestamp: row
                .try_get::<DateTime<Utc>, _>(3)
                .unwrap_or_else(|_| Utc::now()),
            edit_timestamp: row
                .try_get::<DateTime<Utc>, _>(4)
                .unwrap_or_else(|_| Utc::now()),
            user_id: row.try_get(5).unwrap_or_default(),
            views: row.try_get(6).unwrap_or(0),
            page_title: row.try_get(7).unwrap_or_default(),
            favicon_url: row.try_get(8).unwrap_or_default(),
            embed_description: row.try_get(9).unwrap_or_default(),
            embed_image_url: row.try_get(10).unwrap_or_default(),
            embed_color: row.try_get(11).unwrap_or_default(),
        })
        .collect();

    Ok(PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    })
}

pub async fn view_dashboard(
    data: web::Data<AppState>,
    query: web::Query<DashboardQuery>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret)
            .and_then(|opt| opt.ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))),
        &data,
        &jwt_secret,
        &req
    );

    let pool = &data.db_pool;

    let PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    } = try_or_handle!(fetch_user_pastes(pool, &user_id, &query).await, &data, &jwt_secret, &req);

    let mut context = tera::Context::new();
    context.insert("pastes", &pastes);
    context.insert("user_id", &user_id);
    context.insert("site_name", "pastry");
    context.insert("page", &page);
    context.insert("total_pages", &pagination.total_pages);
    context.insert("total_count", &total_count);
    context.insert("has_next", &pagination.has_next);
    context.insert("has_prev", &pagination.has_prev);
    context.insert("search", &query.search);
    context.insert("sort", &query.sort);

    let flash_messages: Vec<FlashMessage> = match extract_flash_message(&req) {
        Some(flash) => vec![flash],
        None => vec![],
    };
    context.insert("flash_messages", &flash_messages);

    try_or_handle!(setup_user_context(&mut context, &data, &req, &jwt_secret).await, &data, &jwt_secret, &req);

    let mut response = with_no_cache_headers(HttpResponse::Ok());
    let csrf_token = get_or_set_csrf_token(&req, &mut response);
    context.insert("csrf_token", &csrf_token);

    response.content_type("text/html");

    clear_flash_cookie(&mut response);

    let rendered = try_or_handle!(
        render_template(&data.tera, "dashboard.html", &context),
        &data,
        &jwt_secret,
        &req
    );

    Ok(response.body(rendered))
}

pub async fn api_search_pastes(
    data: web::Data<AppState>,
    query: web::Query<DashboardQuery>,
    req: HttpRequest,
    jwt_secret: web::Data<String>,
) -> Result<HttpResponse, AppError> {
    let user_id = try_or_handle!(
        get_user_id_from_jwt(&req, &jwt_secret)
            .and_then(|opt| opt.ok_or_else(|| AppError::Unauthorized("User not logged in".to_string()))),
        &data,
        &jwt_secret,
        &req
    );

    let pool = &data.db_pool;

    let PasteResult {
        pastes,
        page,
        total_count,
        pagination,
    } = try_or_handle!(fetch_user_pastes(pool, &user_id, &query).await, &data, &jwt_secret, &req);

    let response = serde_json::json!({
        "pastes": pastes,
        "page": page,
        "total_pages": pagination.total_pages,
        "total_count": total_count,
        "has_next": pagination.has_next,
        "has_prev": pagination.has_prev,
    });

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .json(response))
}