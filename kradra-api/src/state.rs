use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use std::env;

use crate::infra::crypto::passwords::Argon2Hasher;
use crate::infra::crypto::tokens::{JwtAccessVerifier, JwtIssuer, RefreshService};
use crate::infra::db::refresh_token_store::PgRefreshTokenStore;
use crate::infra::db::user_repo::PgUserRepo;

#[derive(Clone)]
pub struct AppState {
    pub db_adapters: DbAdapters,
    pub crypto_adapters: CryptoAdapters,
}

impl AppState {
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Load .env if present
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL")?;
        let db = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await?;

        Ok(Self::new(db))
    }

    fn new(db: PgPool) -> Self {
        Self {
            db_adapters: DbAdapters::new(db),
            crypto_adapters: CryptoAdapters::default(),
        }
    }
}

#[derive(Clone)]
pub struct DbAdapters {
    pub db: PgPool,
    pub user_repo: PgUserRepo,
    pub refresh_token_store: PgRefreshTokenStore,
}

impl DbAdapters {
    fn new(db: PgPool) -> Self {
        let user_repo = PgUserRepo::new(db.clone());
        let refresh_token_store = PgRefreshTokenStore::new(db.clone());

        Self {
            db,
            user_repo,
            refresh_token_store,
        }
    }
}

#[derive(Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub access_ttl_seconds: i64,
    pub refresh_ttl_days: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        let jwt_secret =
            env::var("JWT_SECRET").unwrap_or_else(|_| "change_me_dev_secret".to_string());

        let access_ttl_seconds = env::var("ACCESS_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(900);

        let refresh_ttl_days = env::var("REFRESH_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(30);

        Self {
            jwt_secret,
            access_ttl_seconds,
            refresh_ttl_days,
        }
    }
}

#[derive(Clone)]
pub struct CryptoAdapters {
    pub auth_config: AuthConfig,
    pub password_hasher: Argon2Hasher,
    pub token_issuer: JwtIssuer,
    pub access_verifier: JwtAccessVerifier,
    pub refresh_service: RefreshService,
}

impl Default for CryptoAdapters {
    fn default() -> Self {
        let auth_config = AuthConfig::default();

        let jwt_secret = auth_config.jwt_secret.clone();
        let access_ttl_seconds = auth_config.access_ttl_seconds;

        Self {
            auth_config,
            password_hasher: Argon2Hasher::default(),
            token_issuer: JwtIssuer {
                jwt_secret: jwt_secret.clone(),
                access_ttl_seconds,
            },
            access_verifier: JwtAccessVerifier { jwt_secret },
            refresh_service: RefreshService::default(),
        }
    }
}
