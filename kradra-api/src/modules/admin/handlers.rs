use axum::{
    Json,
    extract::{Path, State},
};

use kradra_core::auth::{
    models::{AuthUser, Role},
    ports::{AppSettingsStore, RefreshTokenStore, UserRepo},
};

use super::dto::{
    AdminRegistrationSettingsResponse, AdminUpdateRegistrationSettingsRequest,
    AdminUpdateUserActiveRequest, AdminUpdateUserRoleRequest, AdminUserDto, AdminUserResponse,
    AdminUserSessionDto, AdminUserSessionsResponse, AdminUsersResponse,
};

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

pub async fn update_user_role(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<AdminUpdateUserRoleRequest>,
) -> Result<Json<AdminUserResponse>, AppError> {
    require_admin(&user)?;

    let role =
        Role::try_from(req.role.as_str()).map_err(|_| AppError::bad_request("invalid role"))?;

    state
        .db_adapters
        .user_repo
        .set_role_by_id(&user_id, role)
        .await?;

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

pub async fn update_user_active(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    user: AuthUser,
    Json(req): Json<AdminUpdateUserActiveRequest>,
) -> Result<Json<AdminUserResponse>, AppError> {
    require_admin(&user)?;

    state
        .db_adapters
        .user_repo
        .set_active_by_id(&user_id, req.is_active)
        .await?;

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

pub async fn get_user_sessions(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    user: AuthUser,
) -> Result<Json<AdminUserSessionsResponse>, AppError> {
    require_admin(&user)?;

    state.db_adapters.user_repo.find_by_id(&user_id).await?;

    let sessions = state
        .db_adapters
        .refresh_token_store
        .list_sessions_for_user(&user_id)
        .await?
        .into_iter()
        .map(|session| AdminUserSessionDto {
            id: session.id,
            ip: session.ip,
            user_agent: session.user_agent,
            is_revoked: session.is_revoked,
            is_replaced: session.is_replaced,
            expires_unix: session.expires_unix,
        })
        .collect();

    Ok(Json(AdminUserSessionsResponse { sessions }))
}

pub async fn logout_all_user_sessions(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    user: AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&user)?;

    state.db_adapters.user_repo.find_by_id(&user_id).await?;

    state
        .db_adapters
        .refresh_token_store
        .revoke_all_active_for_user(&user_id)
        .await?;

    Ok(Json(serde_json::json!({})))
}

pub async fn get_registration_settings(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<AdminRegistrationSettingsResponse>, AppError> {
    require_admin(&user)?;

    let registration_enabled = state
        .db_adapters
        .app_settings_store
        .get_registration_enabled()
        .await
        .map_err(AppError::from)?;

    Ok(Json(AdminRegistrationSettingsResponse {
        registration_enabled,
    }))
}

pub async fn update_registration_settings(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<AdminUpdateRegistrationSettingsRequest>,
) -> Result<Json<AdminRegistrationSettingsResponse>, AppError> {
    require_admin(&user)?;

    state
        .db_adapters
        .app_settings_store
        .set_registration_enabled(req.registration_enabled)
        .await
        .map_err(AppError::from)?;

    Ok(Json(AdminRegistrationSettingsResponse {
        registration_enabled: req.registration_enabled,
    }))
}
