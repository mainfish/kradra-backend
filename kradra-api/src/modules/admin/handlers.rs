use axum::{
    Json,
    extract::{Path, State},
};

use kradra_core::auth::{models::AuthUser, ports::UserRepo};

use super::dto::{AdminUserDto, AdminUserResponse, AdminUsersResponse};

use crate::{error::AppError, http::extractors::auth_user::require_admin, state::AppState};

pub async fn ping(user: AuthUser) -> Result<Json<serde_json::Value>, crate::error::AppError> {
    require_admin(&user)?;

    Ok(Json(serde_json::json!({ "message": "admin pong" })))
}
pub async fn list_users(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<AdminUsersResponse>, AppError> {
    require_admin(&user)?;

    let users = state
        .db_adapters
        .user_repo
        .list_users()
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

pub async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    user: AuthUser,
) -> Result<Json<AdminUserResponse>, AppError> {
    require_admin(&user)?;

    let user = state.db_adapters.user_repo.find_by_id(&user_id).await?;

    Ok(Json(AdminUserResponse {
        user: AdminUserDto {
            id: user.id,
            username: user.username,
            role: user.role.to_string(),
            is_active: user.is_active,
            created_at: user.created_at,
        },
    }))
}
