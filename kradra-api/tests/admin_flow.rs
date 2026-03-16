mod test_app;

use serde_json::json;
use test_app::{
    get_user_id_by_username, login_user, promote_to_admin, register_user, spawn_app,
    unique_username,
};

#[tokio::test]
async fn admin_ping_without_token_returns_401() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/api/admin/ping"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn admin_ping_with_non_admin_returns_403() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let login = login_user(&app, &username, "password123").await;
    let access_token = login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/admin/ping"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
async fn admin_ping_with_admin_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("bulka");
    register_user(&app, &username, "bulkagus").await;
    promote_to_admin(&username).await;

    let login = login_user(&app, &username, "bulkagus").await;
    let access_token = login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/admin/ping"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse response body");

    assert_eq!(body["message"], "admin pong");
}

#[tokio::test]
async fn admin_users_without_token_returns_401() {
    let app = spawn_app().await;

    let response = app
        .client
        .get(app.url("/api/admin/users"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn admin_users_with_non_admin_returns_403() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let login = login_user(&app, &username, "password123").await;
    let access_token = login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/admin/users"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 403);
}

#[tokio::test]
async fn admin_users_with_admin_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("bulka");
    register_user(&app, &username, "bulkagus").await;
    promote_to_admin(&username).await;

    let login = login_user(&app, &username, "bulkagus").await;
    let access_token = login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/admin/users"))
        .bearer_auth(access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse response body");

    assert!(body["users"].is_array(), "users must be an array");
    assert!(
        body["users"].as_array().expect("users must be array").len() >= 1,
        "users array should not be empty"
    );
}

#[tokio::test]
async fn admin_get_user_with_admin_returns_200() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let response = app
        .client
        .get(app.url(&format!("/api/admin/users/{}", user_id)))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse response body");

    assert_eq!(body["user"]["username"], username);
}

#[tokio::test]
async fn admin_can_update_user_role() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let response = app
        .client
        .patch(app.url(&format!("/api/admin/users/{}/role", user_id)))
        .bearer_auth(admin_access_token)
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse response body");

    assert_eq!(body["user"]["role"], "admin");
}

#[tokio::test]
async fn admin_can_deactivate_user() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let response = app
        .client
        .patch(app.url(&format!("/api/admin/users/{}/active", user_id)))
        .bearer_auth(admin_access_token)
        .json(&json!({ "is_active": false }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 200);

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("failed to parse response body");

    assert_eq!(body["user"]["is_active"], false);
}

#[tokio::test]
async fn deactivated_user_cannot_login() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let deactivate_response = app
        .client
        .patch(app.url(&format!("/api/admin/users/{}/active", user_id)))
        .bearer_auth(admin_access_token)
        .json(&json!({ "is_active": false }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(deactivate_response.status().as_u16(), 200);

    let login_response = app
        .client
        .post(app.url("/api/auth/login"))
        .json(&json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .expect("login request failed");

    assert_eq!(login_response.status().as_u16(), 403);
}

#[tokio::test]
async fn admin_can_logout_all_user_sessions() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    let password = "password123";
    register_user(&app, &username, password).await;

    let user_login = login_user(&app, &username, password).await;
    let refresh_token = user_login["refresh_token"]
        .as_str()
        .expect("missing refresh_token")
        .to_string();

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let logout_all_response = app
        .client
        .post(app.url(&format!("/api/admin/users/{}/logout-all", user_id)))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(logout_all_response.status().as_u16(), 200);

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
async fn update_user_role_with_invalid_role_returns_400() {
    let app = spawn_app().await;

    let username = unique_username("alice");
    register_user(&app, &username, "password123").await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let user_id = get_user_id_by_username(&app, admin_access_token, &username).await;

    let response = app
        .client
        .patch(app.url(&format!("/api/admin/users/{}/role", user_id)))
        .bearer_auth(admin_access_token)
        .json(&json!({ "role": "superadmin" }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn admin_get_user_for_missing_user_returns_404() {
    let app = spawn_app().await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .get(app.url("/api/admin/users/00000000-0000-0000-0000-000000000000"))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn update_user_active_for_missing_user_returns_404() {
    let app = spawn_app().await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .patch(app.url("/api/admin/users/00000000-0000-0000-0000-000000000000/active"))
        .bearer_auth(admin_access_token)
        .json(&json!({ "is_active": false }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn update_user_role_for_missing_user_returns_404() {
    let app = spawn_app().await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .patch(app.url("/api/admin/users/00000000-0000-0000-0000-000000000000/role"))
        .bearer_auth(admin_access_token)
        .json(&json!({ "role": "admin" }))
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn logout_all_for_missing_user_returns_404() {
    let app = spawn_app().await;

    let admin_username = unique_username("bulka");
    register_user(&app, &admin_username, "bulkagus").await;
    promote_to_admin(&admin_username).await;

    let admin_login = login_user(&app, &admin_username, "bulkagus").await;
    let admin_access_token = admin_login["access_token"]
        .as_str()
        .expect("missing access_token");

    let response = app
        .client
        .post(app.url("/api/admin/users/00000000-0000-0000-0000-000000000000/logout-all"))
        .bearer_auth(admin_access_token)
        .send()
        .await
        .expect("request failed");

    assert_eq!(response.status().as_u16(), 404);
}
