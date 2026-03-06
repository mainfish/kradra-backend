use axum::Json;
use serde_json::json;

pub async fn ping() -> Json<serde_json::Value> {
    Json(json!({
        "ok": false,
        "stub": true,
        "message": "admin/ping is not implemented yet"
    }))
}
