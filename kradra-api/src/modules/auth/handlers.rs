use crate::{crypto::passwords, error::AppError, state::AppState};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub id: String,
    pub username: String,
    pub role: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = req.username.trim().to_string();

    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".to_string()));
    }

    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "password must be at least 8 characters".to_string(),
        ));
    }

    let password_hash = passwords::hash_password(&req.password).map_err(|_| AppError::Internal)?;

    let inserted = sqlx::query(
        r#"
        INSERT INTO users (username, password_hash)
        VALUES ($1, $2)
        RETURNING id::text as id, username, role
        "#,
    )
    .bind(&username)
    .bind(&password_hash)
    .fetch_one(&state.db)
    .await;

    let row = match inserted {
        Ok(row) => row,
        Err(err) => {
            // unique_violation
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.code().as_deref() == Some("23505") {
                    return Err(AppError::Conflict("username already exists".to_string()));
                }
            }
            return Err(AppError::Internal);
        }
    };

    let user = RegisterResponse {
        id: row
            .try_get::<String, _>("id")
            .map_err(|_| AppError::Internal)?,
        username: row
            .try_get::<String, _>("username")
            .map_err(|_| AppError::Internal)?,
        role: row
            .try_get::<String, _>("role")
            .map_err(|_| AppError::Internal)?,
    };

    Ok(Json(json!({ "user": user })))
}

pub async fn login() -> Json<serde_json::Value> {
    Json(json!({
        "stub": true,
        "message": "auth/login is not implemented yet"
    }))
}

pub async fn refresh() -> Json<serde_json::Value> {
    Json(json!({
        "stub": true,
        "message": "auth/refresh is not implemented yet"
    }))
}

pub async fn logout() -> Json<serde_json::Value> {
    Json(json!({
        "stub": true,
        "message": "auth/logout is not implemented yet"
    }))
}
