use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use kradra_api::{AppState, build_router};
use serde_json::json;
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

pub fn unique_username(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();

    format!("{}_{}", prefix, nanos)
}

pub async fn register_user(app: &TestApp, username: &str, password: &str) -> serde_json::Value {
    let response = app
        .client
        .post(app.url("/api/auth/register"))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("register request failed");

    assert_eq!(
        response.status().as_u16(),
        200,
        "unexpected register status"
    );

    response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse register response")
}

pub async fn login_user(app: &TestApp, username: &str, password: &str) -> serde_json::Value {
    let response = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(response.status().as_u16(), 200, "unexpected login status");

    response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse login response")
}

pub async fn promote_to_admin(username: &str) {
    let database_url = std::env::var("DATABASE_URL_TEST").expect("DATABASE_URL_TEST is not set");

    let pool = PgPool::connect(&database_url)
        .await
        .expect("failed to connect to test database");

    let result = sqlx::query(
        r#"
        UPDATE users
        SET role = 'admin'
        WHERE username = $1
        "#,
    )
    .bind(username)
    .execute(&pool)
    .await
    .expect("failed to promote user to admin");

    assert_eq!(
        result.rows_affected(),
        1,
        "expected exactly one updated user"
    );
}

pub async fn get_user_id_by_username(
    app: &TestApp,
    admin_access_token: &str,
    username: &str,
) -> String {
    let users_response = app
        .client
        .get(app.url("/api/admin/users"))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(users_response.status().as_u16(), 200);

    let users_body = users_response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse users response");

    users_body["users"]
        .as_array()
        .expect("users must be array")
        .iter()
        .find(|user| user["username"] == username)
        .and_then(|user| user["id"].as_str())
        .expect("failed to find created user id")
        .to_string()
}
