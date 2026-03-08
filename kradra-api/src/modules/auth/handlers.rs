use super::dto::{
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, RefreshRequest, RefreshResponse,
    RegisterRequest, RegisterResponse, RegisterUser,
};
use crate::{error::AppError, state::AppState};
use axum::{Json, extract::State};

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let username = req.username.trim().to_string();

    if username.is_empty() {
        return Err(AppError::bad_request("username is required"));
    }

    if req.password.len() < 8 {
        return Err(AppError::bad_request(
            "password must be at least 8 characters",
        ));
    }

    let created = kradra_core::auth::usecases::register(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &username,
        &req.password,
    )
    .await
    .map_err(AppError::from)?;

    let user = RegisterUser {
        id: created.id,
        username: created.username,
        role: created.role.to_string(),
    };

    Ok(Json(RegisterResponse { user }))
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let out = kradra_core::auth::usecases::login(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &req.username,
        &req.password,
        state.crypto_adapters.auth_config.access_ttl_seconds,
        state.crypto_adapters.auth_config.refresh_ttl_days,
    )
    .await
    .map_err(AppError::from)?;

    Ok(Json(LoginResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        token_type: out.token_type,
        expires_in: out.expires_in,
    }))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let out = kradra_core::auth::usecases::refresh(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &req.refresh_token,
        state.crypto_adapters.auth_config.access_ttl_seconds,
        state.crypto_adapters.auth_config.refresh_ttl_days,
    )
    .await
    .map_err(AppError::from)?;

    Ok(Json(RefreshResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        token_type: out.token_type,
        expires_in: out.expires_in,
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<LogoutResponse>, AppError> {
    kradra_core::auth::usecases::logout(
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &req.refresh_token,
    )
    .await
    .map_err(AppError::from)?;

    Ok(Json(LogoutResponse {}))
}
