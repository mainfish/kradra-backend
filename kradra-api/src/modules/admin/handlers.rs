use axum::{Json, extract::State};

use kradra_core::auth::models::AuthUser;

use super::dto::{AdminUserDto, AdminUsersResponse};

use crate::{error::AppError, http::extractors::auth_user::require_admin, state::AppState};

pub async fn ping(user: AuthUser) -> Result<Json<serde_json::Value>, crate::error::AppError> {
    require_admin(&user)?;

    Ok(Json(serde_json::json!({ "message": "admin pong" })))
}

pub async fn users_list(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<AdminUsersResponse>, AppError> {
    require_admin(&user)?;

    let users = state
        .db_adapters
        .user_repo
        .users_list()
        .await?
        .into_iter()
        .map(|user| AdminUserDto {
            id: user.id,
            username: user.username,
            role: user.role.to_string(),
            is_active: user.is_active,
            created_at: user.created_at,
        })
        .collect();

    Ok(Json(AdminUsersResponse { users }))
}
