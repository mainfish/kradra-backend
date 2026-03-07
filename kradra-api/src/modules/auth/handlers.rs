use crate::{crypto::passwords, error::AppError, state::AppState};
use axum::{Json, extract::State};
use serde_json::json;
use sqlx::Row;

use super::dto::{LoginRequest, LoginResponse, RegisterRequest, RegisterResponse, RegisterUser};

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
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

    let user = RegisterUser {
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

    Ok(Json(RegisterResponse { user }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let username = req.username.trim().to_string();
    if username.is_empty() {
        return Err(AppError::BadRequest("username is required".to_string()));
    }

    let row = sqlx::query(
        r#"
        SELECT id::text as id, username, password_hash, role, is_active
        FROM users
        WHERE username = $1
        "#,
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| AppError::Internal)?;

    let Some(row) = row else {
        return Err(AppError::Unauthorized);
    };

    let is_active: bool = row.try_get("is_active").map_err(|_| AppError::Internal)?;
    if !is_active {
        return Err(AppError::Unauthorized);
    }

    let user_id: String = row.try_get("id").map_err(|_| AppError::Internal)?;
    let role: String = row.try_get("role").map_err(|_| AppError::Internal)?;
    let password_hash: String = row
        .try_get("password_hash")
        .map_err(|_| AppError::Internal)?;

    let ok = passwords::verify_password(&req.password, &password_hash)
        .map_err(|_| AppError::Internal)?;
    if !ok {
        return Err(AppError::Unauthorized);
    }

    // access jwt
    let access_token = crate::crypto::tokens::make_access_token(
        &user_id,
        &username,
        &role,
        &state.auth.jwt_secret,
        state.auth.access_ttl_seconds,
    )
    .map_err(|_| AppError::Internal)?;

    // refresh token (plain to client, hash to DB)
    let (refresh_token, refresh_hash) = crate::crypto::tokens::make_refresh_token();
    let expires_unix =
        crate::crypto::tokens::unix_now() + state.auth.refresh_ttl_days * 24 * 60 * 60;

    sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES (($1)::uuid, $2, to_timestamp($3))
        "#,
    )
    .bind(&user_id)
    .bind(&refresh_hash)
    .bind(expires_unix)
    .execute(&state.db)
    .await
    .map_err(|_| AppError::Internal)?;

    Ok(Json(json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": state.auth.access_ttl_seconds
    })))
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
