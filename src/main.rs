use actix_files::Files;
use actix_web::web;
use actix_web::web::{ServiceConfig, PayloadConfig};
use shuttle_runtime::SecretStore;
use shuttle_actix_web::ShuttleActixWeb;
use sqlx::PgPool;
use std::sync::Arc;

mod common;
mod handlers;
mod jws;
mod models;
mod state;

use crate::state::AppState;
use crate::handlers::{dashboard, paste, user, admin, profile, friendship, notifications};

fn config_app(
    app_state: Arc<AppState>,
    jwt_secret: String,
    cfg: &mut ServiceConfig,
) {
    cfg.app_data(web::Data::from(app_state))
       .app_data(web::Data::new(jwt_secret))
       .app_data(PayloadConfig::new(5 * 1024 * 1024))
       .route("/", web::get().to(paste::index))
       .route("/save", web::post().to(paste::save_paste))
       .route("/raw/{token}/css", web::get().to(paste::view_raw_css))
       .route("/register", web::get().to(user::register_form))
       .route("/register", web::post().to(user::register))
       .route("/welcome", web::get().to(user::register_success))
       .route("/login", web::get().to(user::login_form))
       .route("/login", web::post().to(user::login))
       .route("/logout", web::get().to(user::logout))
       .route("/profile/{username}", web::get().to(profile::view_profile))
       .route("/profile/{username}/edit", web::post().to(profile::update_profile))
       .route("/api/profile/{username}/friends", web::get().to(profile::api_profile_friends))
       .route("/profile/{username}/badge/{badge_type}/assign", web::post().to(profile::assign_badge))
       .route("/profile/{username}/badge/{badge_type}/remove", web::post().to(profile::remove_badge))
       .route("/profile/{username}/refresh-token", web::post().to(user::refresh_user_token))
       .route("/friend/add/{username}", web::post().to(friendship::add_friend))
       .route("/friend/remove/{username}", web::post().to(friendship::remove_friend))
       .route("/friend-requests", web::get().to(friendship::get_friend_requests))
       .route("/friend-request/respond/{sender}/{action}", web::post().to(friendship::respond_friend_request))
       .route("/api/notifications", web::get().to(notifications::get_notifications_api))
       .route("/api/notifications/mark-read", web::post().to(notifications::mark_notifications_read))
       .route("/api/notifications/dismiss_all", web::post().to(notifications::dismiss_all_notifications))
       .route("/dashboard", web::get().to(dashboard::view_dashboard))
       .route("/admin/panel", web::get().to(admin::admin_panel))
       .route("/admin/pastes", web::get().to(admin::admin_pastes))
       .route("/admin/pastes/{token}/delete", web::post().to(admin::admin_delete_paste))
       .route("/admin/users", web::get().to(admin::admin_users))
       .route("/admin/ban", web::post().to(admin::ban_user))
       .route("/admin/unban", web::post().to(admin::unban_user))
       .route("/admin/delete_profile/{username}", web::post().to(profile::delete_profile_admin))
       .route("/api/pastes", web::get().to(dashboard::api_search_pastes))
       .route("/{token}", web::get().to(paste::view_paste))
       .route("/edit/{token}", web::get().to(paste::edit_paste_form))
       .route("/edit/{token}", web::post().to(paste::edit_paste));
}

#[shuttle_runtime::main]
async fn main(
    #[shuttle_shared_db::Postgres] db_url: String,
    #[shuttle_runtime::Secrets] secret_store: SecretStore,
) -> ShuttleActixWeb<impl Fn(&mut ServiceConfig) + Clone + Send + 'static> {
    let jwt_secret = secret_store
        .get("JWT_SECRET")
        .expect("JWT_SECRET must be set in Secrets.toml");

    let pool = PgPool::connect(&db_url)
        .await
        .expect("Failed to connect to the database");

    let app_state = state::create_app_state(pool)
        .await
        .expect("Failed to create app state");
    let app_state = Arc::new(app_state);

    let jwt_secret_clone = jwt_secret.clone();
    let app_state_clone = Arc::clone(&app_state);

    Ok(shuttle_actix_web::ActixWebService(move |cfg: &mut ServiceConfig| {
        let app_data_state = web::Data::from(app_state_clone.clone());
        let app_data_jwt = web::Data::new(jwt_secret_clone.clone());

        cfg.app_data(app_data_state.clone())
           .app_data(app_data_jwt.clone())
           .service(Files::new("/static", "./static").show_files_listing())
           .configure(|cfg| config_app(app_state_clone.clone(), jwt_secret_clone.clone(), cfg));
    }))
}