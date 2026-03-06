use axum::{Json, extract::State};
use serde_json::json;

use crate::{error::AppError, state::AppState};

pub async fn root() -> &'static str {
    "backend is alive"
}

pub async fn health() -> &'static str {
    "ok"
}

pub async fn ping() -> Json<serde_json::Value> {
    Json(json!({
        "ok": true,
        "service": "kradra-api",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

pub async fn readiness(State(state): State<AppState>) -> Result<&'static str, AppError> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|e| AppError::ServiceUnavailable(format!("db unavailable: {e}")))?;

    Ok("ok")
}
