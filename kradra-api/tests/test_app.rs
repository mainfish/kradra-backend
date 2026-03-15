use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use kradra_api::{AppState, build_router};
use sqlx::{PgPool, postgres::PgPoolOptions};

fn test_lock() -> Arc<tokio::sync::Mutex<()>> {
    static LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    LOCK.get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

pub struct TestApp {
    pub address: String,
    pub client: reqwest::Client,
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

impl TestApp {
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.address, path)
    }
}

async fn test_db_pool() -> PgPool {
    dotenvy::dotenv().ok();

    let database_url = std::env::var("DATABASE_URL_TEST").expect("DATABASE_URL_TEST is not set");

    PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("failed to connect to test database")
}

async fn reset_db(pool: &PgPool) {
    sqlx::query("DELETE FROM refresh_tokens")
        .execute(pool)
        .await
        .expect("failed to delete refresh_tokens");

    sqlx::query("DELETE FROM users")
        .execute(pool)
        .await
        .expect("failed to delete users");
}

pub async fn spawn_app() -> TestApp {
    let guard = test_lock().lock_owned().await;

    let db = test_db_pool().await;
    reset_db(&db).await;

    let app_state = AppState::new(db);
    let app = build_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind random port");

    let addr: SocketAddr = listener.local_addr().expect("failed to read local addr");

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    );

    tokio::spawn(async move {
        server.await.expect("test server crashed");
    });

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .expect("failed to build reqwest client");

    TestApp {
        address: format!("http://{}", addr),
        client,
        _guard: guard,
    }
}
