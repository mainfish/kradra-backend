use axum::{Json, extract::State, http::HeaderMap};

use super::dto::{
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, RefreshRequest, RefreshResponse,
    RegisterRequest, RegisterResponse, RegisterUser,
};
use crate::{error::AppError, http::cookies, state::AppState};

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
    request_headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), AppError> {
    let is_web = cookies::csrf::is_web_request(&request_headers);

    let access_ttl_seconds = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_ttl_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = kradra_core::auth::usecases::login(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &req.username,
        &req.password,
        access_ttl_seconds,
        refresh_ttl_days,
    )
    .await
    .map_err(AppError::from)?;

    let response_headers = cookies::refresh::issue_session_cookies(&state, &out.refresh_token)?;

    Ok((
        response_headers,
        Json(LoginResponse {
            access_token: out.access_token,
            refresh_token: if is_web {
                None
            } else {
                Some(out.refresh_token)
            },
            token_type: out.token_type,
            expires_in: out.expires_in,
        }),
    ))
}

pub async fn refresh(
    State(state): State<AppState>,
    request_headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<(HeaderMap, Json<RefreshResponse>), AppError> {
    let is_web = cookies::csrf::is_web_request(&request_headers);

    cookies::csrf::enforce_csrf_if_web(&request_headers)?;

    let refresh_token =
        cookies::refresh::resolve_refresh_token(&request_headers, req.refresh_token)
            .ok_or(AppError::Unauthorized)?;

    let access_ttl_seconds = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_ttl_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = kradra_core::auth::usecases::refresh(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
        access_ttl_seconds,
        refresh_ttl_days,
    )
    .await
    .map_err(AppError::from)?;

    let response_headers = cookies::refresh::rotate_session_cookies(&state, &out.refresh_token)?;

    Ok((
        response_headers,
        Json(RefreshResponse {
            access_token: out.access_token,
            refresh_token: if is_web {
                None
            } else {
                Some(out.refresh_token)
            },
            token_type: out.token_type,
            expires_in: out.expires_in,
        }),
    ))
}

pub async fn logout(
    State(state): State<AppState>,
    request_headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> Result<(HeaderMap, Json<LogoutResponse>), AppError> {
    cookies::csrf::enforce_csrf_if_web(&request_headers)?;

    let refresh_token =
        cookies::refresh::resolve_refresh_token(&request_headers, req.refresh_token)
            .ok_or(AppError::Unauthorized)?;

    kradra_core::auth::usecases::logout(
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
    )
    .await
    .map_err(AppError::from)?;

    let response_headers = cookies::refresh::clear_session_cookies(&state)?;

    Ok((response_headers, Json(LogoutResponse {})))
}

pub async fn csrf(
    State(state): State<AppState>,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let response_headers = cookies::csrf::issue_csrf_cookie(&state)?;
    Ok((response_headers, Json(serde_json::json!({}))))
}
