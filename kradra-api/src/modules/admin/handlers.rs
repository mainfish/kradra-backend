use axum::Json;

use kradra_core::auth::models::AuthUser;

use crate::http::extractors::auth_user::require_admin;

pub async fn ping(user: AuthUser) -> Result<Json<serde_json::Value>, crate::error::AppError> {
    require_admin(&user)?;

    Ok(Json(serde_json::json!({ "message": "admin pong" })))
}
