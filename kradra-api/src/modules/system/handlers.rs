use axum::{Json, extract::State};
use serde_json::json;

use crate::{error::AppError, state::AppState};

pub async fn root() -> &'static str {
    "kradra"
}

pub async fn health() -> &'static str {
    "alive"
}

pub async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({
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
