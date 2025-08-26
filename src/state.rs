use sqlx::migrate::Migrator;
use std::path::Path;
use sqlx::PgPool;
use tera::Tera;

pub struct AppState {
    pub db_pool: PgPool,
    pub tera: Tera,
}

pub async fn create_app_state(pool: PgPool) -> Result<AppState, Box<dyn std::error::Error>> {
    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&pool).await?;

    let tera = Tera::new("templates/**/*")?;

    Ok(AppState {
        db_pool: pool,
        tera,
    })
}
