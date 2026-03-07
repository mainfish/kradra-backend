use crate::{crypto::passwords, error::AppError, state::AppState};
use axum::{Json, extract::State};
use sqlx::Row;

use super::dto::{
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, RefreshRequest, RefreshResponse,
    RegisterRequest, RegisterResponse, RegisterUser,
};

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
) -> Result<Json<LoginResponse>, AppError> {
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

    Ok(Json(LoginResponse {
        access_token: access_token,
        refresh_token: refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: state.auth.access_ttl_seconds,
    }))
}

/// ✅ refresh rotation + reuse detection (kill all active refresh tokens for user if reuse detected)
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    if req.refresh_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "refresh_token is required".to_string(),
        ));
    }

    let old_hash = crate::crypto::tokens::hash_refresh_token(req.refresh_token.trim());
    let now_unix = crate::crypto::tokens::unix_now();
    let new_expires_unix = now_unix + state.auth.refresh_ttl_days * 24 * 60 * 60;

    let mut tx = state.db.begin().await.map_err(|_| AppError::Internal)?;

    // 1) Find refresh token row (lock it) to support rotation + reuse detection
    let row = sqlx::query(
        r#"
        SELECT
          id::text as id,
          user_id::text as user_id,
          revoked_at IS NOT NULL as is_revoked,
          replaced_by IS NOT NULL as is_replaced,
          expires_at > now() as not_expired
        FROM refresh_tokens
        WHERE token_hash = $1
        FOR UPDATE
        "#,
    )
    .bind(&old_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| AppError::Internal)?;

    let Some(row) = row else {
        tx.rollback().await.ok();
        return Err(AppError::Unauthorized);
    };

    let old_id: String = row.try_get("id").map_err(|_| AppError::Internal)?;
    let user_id: String = row.try_get("user_id").map_err(|_| AppError::Internal)?;

    let is_revoked: bool = row.try_get("is_revoked").map_err(|_| AppError::Internal)?;
    let is_replaced: bool = row.try_get("is_replaced").map_err(|_| AppError::Internal)?;
    let not_expired: bool = row.try_get("not_expired").map_err(|_| AppError::Internal)?;

    // expired refresh token -> unauthorized (no reuse response)
    if !not_expired {
        tx.rollback().await.ok();
        return Err(AppError::Unauthorized);
    }

    // reuse detection: token was already used (replaced) or explicitly revoked
    if is_revoked || is_replaced {
        // revoke all active refresh tokens for this user (token family / all sessions)
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = now()
            WHERE user_id = ($1)::uuid
              AND revoked_at IS NULL
            "#,
        )
        .bind(&user_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AppError::Internal)?;

        tx.commit().await.map_err(|_| AppError::Internal)?;
        return Err(AppError::Unauthorized);
    }

    // 2) Load user fields needed for new access token
    let user = sqlx::query(
        r#"
        SELECT username, role, is_active
        FROM users
        WHERE id = ($1)::uuid
        "#,
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AppError::Internal)?;

    let is_active: bool = user.try_get("is_active").map_err(|_| AppError::Internal)?;
    if !is_active {
        tx.rollback().await.ok();
        return Err(AppError::Unauthorized);
    }

    let username: String = user.try_get("username").map_err(|_| AppError::Internal)?;
    let role: String = user.try_get("role").map_err(|_| AppError::Internal)?;

    // 3) Create new refresh token row
    let (new_refresh_plain, new_refresh_hash) = crate::crypto::tokens::make_refresh_token();

    let new_row = sqlx::query(
        r#"
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
        VALUES (($1)::uuid, $2, to_timestamp($3))
        RETURNING id::text as id
        "#,
    )
    .bind(&user_id)
    .bind(&new_refresh_hash)
    .bind(new_expires_unix)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| AppError::Internal)?;

    let new_id: String = new_row.try_get("id").map_err(|_| AppError::Internal)?;

    // 4) Revoke old refresh token and link to new
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = now(), replaced_by = ($2)::uuid
        WHERE id = ($1)::uuid
        "#,
    )
    .bind(&old_id)
    .bind(&new_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| AppError::Internal)?;

    tx.commit().await.map_err(|_| AppError::Internal)?;

    // 5) New access token (stateless)
    let access_token = crate::crypto::tokens::make_access_token(
        &user_id,
        &username,
        &role,
        &state.auth.jwt_secret,
        state.auth.access_ttl_seconds,
    )
    .map_err(|_| AppError::Internal)?;

    Ok(Json(RefreshResponse {
        access_token,
        refresh_token: new_refresh_plain,
        token_type: "Bearer".to_string(),
        expires_in: state.auth.access_ttl_seconds,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    if req.refresh_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "refresh_token is required".to_string(),
        ));
    }

    let hash = crate::crypto::tokens::hash_refresh_token(req.refresh_token.trim());

    // revoke if exists and not already revoked
    sqlx::query(
        r#"
        UPDATE refresh_tokens
        SET revoked_at = now()
        WHERE token_hash = $1
          AND revoked_at IS NULL
        "#,
    )
    .bind(&hash)
    .execute(&state.db)
    .await
    .map_err(|_| AppError::Internal)?;

    Ok(Json(LogoutResponse {}))
}
