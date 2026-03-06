use axum::Json;
use serde_json::json;

pub async fn register() -> Json<serde_json::Value> {
    Json(json!({
        "ok": false,
        "stub": true,
        "message": "auth/register is not implemented yet"
    }))
}

pub async fn login() -> Json<serde_json::Value> {
    Json(json!({
        "ok": false,
        "stub": true,
        "message": "auth/login is not implemented yet"
    }))
}

pub async fn refresh() -> Json<serde_json::Value> {
    Json(json!({
        "ok": false,
        "stub": true,
        "message": "auth/refresh is not implemented yet"
    }))
}

pub async fn logout() -> Json<serde_json::Value> {
    Json(json!({
        "ok": false,
        "stub": true,
        "message": "auth/logout is not implemented yet"
    }))
}
