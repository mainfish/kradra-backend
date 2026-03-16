mod test_app;

use reqwest::header::SET_COOKIE;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use test_app::{TestApp, spawn_app};

fn unique_username(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();

    format!("{}_{}", prefix, nanos)
}

fn cookie_value_from_headers(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|raw| {
            raw.split(';')
                .next()
                .and_then(|first| first.split_once('='))
                .and_then(|(cookie_name, cookie_value)| {
                    if cookie_name == name {
                        Some(cookie_value.to_string())
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_else(|| panic!("missing cookie {}", name))
}

async fn register_user(app: &TestApp, username: &str, password: &str) -> serde_json::Value {
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

async fn login_user(app: &TestApp, username: &str, password: &str) -> serde_json::Value {
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

#[tokio::test]
async fn register_success_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let body = register_user(&app, &username, "password123").await;

    assert_eq!(body["user"]["username"], username);
    assert_eq!(body["user"]["role"], "user");
    assert!(body["user"]["id"].is_string());
}

#[tokio::test]
async fn login_success_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let body = login_user(&app, &username, "password123").await;

    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());
}

#[tokio::test]
async fn login_with_wrong_password_returns_401() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let response = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({
            "username": username,
            "password": "wrongpass"
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn me_with_valid_access_token_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let login = login_user(&app, &username, "password123").await;
    let access_token = login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/me"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let raw = response.text().await.expect("failed to read me response");
    let body: serde_json::Value = serde_json::from_str(&raw).expect("failed to parse me response");

    assert!(
        body["username"].is_string()
            || body["user"]["username"].is_string()
            || body["id"].is_string()
            || body["sub"].is_string(),
        "unexpected /api/me shape: {}",
        body
    );
}

#[tokio::test]
async fn me_without_token_returns_401() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/api/me"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn refresh_rotates_token() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login = login_user(&app, &username, password).await;
    let old_refresh_token = login["refresh_token"]
        .as_str()
        .expect("missing refresh_token")
        .to_string();

    let response = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({
            "refresh_token": old_refresh_token
        }))
        .send()
        .await
        .expect("refresh request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse refresh response");

    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());

    let new_refresh_token = body["refresh_token"]
        .as_str()
        .expect("missing rotated refresh_token");

    assert_ne!(new_refresh_token, old_refresh_token);
}

#[tokio::test]
async fn old_refresh_token_returns_401() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login = login_user(&app, &username, password).await;
    let old_refresh_token = login["refresh_token"]
        .as_str()
        .expect("missing refresh_token")
        .to_string();

    let first_refresh = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({
            "refresh_token": old_refresh_token
        }))
        .send()
        .await
        .expect("first refresh request failed");

    assert_eq!(first_refresh.status().as_u16(), 200);

    let second_refresh = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({
            "refresh_token": old_refresh_token
        }))
        .send()
        .await
        .expect("second refresh request failed");

    assert_eq!(second_refresh.status().as_u16(), 401);
}

#[tokio::test]
async fn logout_revokes_refresh_token() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login = login_user(&app, &username, password).await;
    let refresh_token = login["refresh_token"]
        .as_str()
        .expect("missing refresh_token")
        .to_string();

    let logout_response = app
        .client
        .post(app.url("/api/auth/logout"))
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(logout_response.status().as_u16(), 200);

    let refresh_response = app
        .client
        .post(app.url("/api/auth/refresh"))
        .json(&json!({
            "refresh_token": refresh_token
        }))
        .send()
        .await
        .expect("refresh request failed");

    assert_eq!(refresh_response.status().as_u16(), 401);
}

#[tokio::test]
async fn csrf_endpoint_sets_cookie() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/api/auth/csrf"))
        .send()
        .await
        .expect("csrf request failed");

    assert_eq!(response.status().as_u16(), 200);

    let csrf_cookie = cookie_value_from_headers(response.headers(), "csrf_token");
    assert!(!csrf_cookie.is_empty());
}

#[tokio::test]
async fn cookie_refresh_without_csrf_returns_403() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .header("origin", "http://localhost:3000")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 200);

    let response = app
        .client
        .post(app.url("/api/auth/refresh"))
        .header("origin", "http://localhost:3000")
        .json(&json!({}))
        .send()
        .await
        .expect("refresh request failed");

    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
async fn cookie_refresh_with_csrf_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .header("origin", "http://localhost:3000")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 200);

    let csrf_token = cookie_value_from_headers(login_response.headers(), "csrf_token");

    let response = app
        .client
        .post(app.url("/api/auth/refresh"))
        .header("origin", "http://localhost:3000")
        .header("x-csrf-token", &csrf_token)
        .json(&json!({}))
        .send()
        .await
        .expect("refresh request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse refresh response");

    assert!(body["access_token"].is_string());
    assert!(body["token_type"].is_string());
    assert!(body["expires_in"].is_number());
    assert!(body["refresh_token"].is_null());
}

#[tokio::test]
async fn cookie_logout_without_csrf_returns_403() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .header("origin", "http://localhost:3000")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 200);

    let response = app
        .client
        .post(app.url("/api/auth/logout"))
        .header("origin", "http://localhost:3000")
        .json(&json!({}))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
async fn cookie_logout_with_csrf_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .header("origin", "http://localhost:3000")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 200);

    let csrf_token = cookie_value_from_headers(login_response.headers(), "csrf_token");

    let response = app
        .client
        .post(app.url("/api/auth/logout"))
        .header("origin", "http://localhost:3000")
        .header("x-csrf-token", &csrf_token)
        .json(&json!({}))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout_then_cookie_refresh_returns_403() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .header("origin", "http://localhost:3000")
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 200);

    let csrf_token = cookie_value_from_headers(login_response.headers(), "csrf_token");

    let logout_response = app
        .client
        .post(app.url("/api/auth/logout"))
        .header("origin", "http://localhost:3000")
        .header("x-csrf-token", &csrf_token)
        .json(&json!({}))
        .send()
        .await
        .expect("logout request failed");

    assert_eq!(logout_response.status().as_u16(), 200);

    let refresh_response = app
        .client
        .post(app.url("/api/auth/refresh"))
        .header("origin", "http://localhost:3000")
        .header("x-csrf-token", &csrf_token)
        .json(&json!({}))
        .send()
        .await
        .expect("refresh request failed");

    assert_eq!(refresh_response.status().as_u16(), 403);
}
