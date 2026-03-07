use sqlx::postgres::PgPoolOptions;
use std::{env, error::Error, net::SocketAddr};

mod crypto;
mod error;
mod http;
mod modules;
mod state;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenvy::dotenv().ok();

    // DB
    let database_url = env::var("DATABASE_URL")?;
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    // Auth config
    let jwt_secret = env::var("JWT_SECRET")?;
    let access_ttl_seconds: i64 = env::var("ACCESS_TTL_SECONDS")
        .unwrap_or_else(|_| "900".to_string())
        .parse()?;
    let refresh_ttl_days: i64 = env::var("REFRESH_TTL_DAYS")
        .unwrap_or_else(|_| "30".to_string())
        .parse()?;
    let auth = state::AuthConfig {
        jwt_secret,
        access_ttl_seconds,
        refresh_ttl_days,
    };

    let app_state = state::AppState { db, auth };
    let app = http::build_router(app_state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:20443".to_string())
        .parse()?;

    println!("listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            eprintln!("🛑 shutdown signal received (Ctrl+C)");
        }
        Err(err) => {
            eprintln!("🛑 failed to install Ctrl+C handler: {err}");
        }
    }
}
