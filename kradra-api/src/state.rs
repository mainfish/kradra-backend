use sqlx::PgPool;

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_days: i64,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub auth: AuthConfig,
}
