use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, Method},
};
use std::{env, sync};

use cookies::{csrf, refresh};
use kradra_core::auth::errors::AuthError;
use kradra_core::auth::usecases;

use super::dto::{
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, RefreshRequest, RefreshResponse,
    RegisterRequest, RegisterResponse, RegisterUser,
};

use crate::infra::security::lockout::LockoutService;
use crate::infra::telemetry::audit;
use crate::{error::AppError, http::cookies, state::AppState};

fn registration_disabled() -> bool {
    env::var("DISABLE_REGISTRATION")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, AppError> {
    let meta = audit::RequestMeta::from_headers(Method::POST, "/api/auth/register", &headers);
    let username = req.username.trim().to_string();

    if registration_disabled() {
        audit::auth_register_fail(&meta, &username, "registration_disabled");

        return Err(AppError::ServiceUnavailable(
            "registration temporarily disabled".to_string(),
        ));
    }

    if username.is_empty() {
        audit::auth_register_fail(&meta, "", "username_empty");

        return Err(AppError::bad_request("username is required"));
    }

    if req.password.len() < 8 {
        audit::auth_register_fail(&meta, &username, "password_too_short");

        return Err(AppError::bad_request(
            "password must be at least 8 characters",
        ));
    }

    let created = match usecases::register(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &username,
        &req.password,
    )
    .await
    {
        Ok(value) => value,
        Err(err) => {
            let reason = audit::auth_error_reason(&err);
            audit::auth_register_fail(&meta, &username, reason);

            return Err(AppError::from(err));
        }
    };

    audit::auth_register_success(&meta, &created.username, &created.id);

    let user = RegisterUser {
        id: created.id,
        username: created.username,
        role: created.role.to_string(),
    };

    Ok(Json(RegisterResponse { user }))
}

pub async fn login(
    State(state): State<AppState>,
    Extension(login_slowdown): Extension<
        sync::Arc<crate::infra::security::slowdown::LoginSlowdown>,
    >,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), AppError> {
    let meta = audit::RequestMeta::from_headers(Method::POST, "/api/auth/login", &headers);
    let is_web = csrf::is_web_request(&headers);

    let ip = meta.ip.clone();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string())
        .clone();
    let username_key = req.username.clone();

    login_slowdown.maybe_delay(&ip, &username_key).await;

    let lockout_service = LockoutService::from_env();

    let lockout_check = lockout_service
        .check(&state.db_adapters.user_repo, &req.username)
        .await
        .map_err(AppError::from)?;

    if lockout_check.is_locked {
        audit::auth_login_fail(&meta, &req.username, "locked");

        return Err(AppError::Locked("account locked".to_string()));
    }

    let access_ttl_seconds = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_ttl_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = match usecases::login(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &state.crypto_adapters.access_token_service,
        &state.crypto_adapters.refresh_token_service,
        &state.db_adapters.refresh_token_store,
        &req.username,
        &req.password,
        &ip,
        user_agent,
        access_ttl_seconds,
        refresh_ttl_days,
    )
    .await
    {
        Ok(value) => {
            audit::auth_login_success(&meta, &req.username);

            login_slowdown.reset(&ip, &username_key).await;

            if let Some(user_id) = lockout_check.user_id.as_deref() {
                lockout_service
                    .reset_on_success(&state.db_adapters.user_repo, user_id)
                    .await
                    .map_err(AppError::from)?;
            }

            value
        }
        Err(err) => {
            if matches!(err, AuthError::InvalidCredentials) {
                login_slowdown.record_failure(&ip, &username_key).await;

                if let Some(user_id) = lockout_check.user_id.as_deref() {
                    let triggered = lockout_service
                        .record_failure(&state.db_adapters.user_repo, user_id)
                        .await
                        .map_err(AppError::from)?;

                    if triggered {
                        audit::auth_lockout_triggered(&meta, &req.username, user_id);
                    }
                }
            }

            let reason = audit::auth_error_reason(&err);
            audit::auth_login_fail(&meta, &req.username, reason);

            return Err(AppError::from(err));
        }
    };

    let response_headers = refresh::issue_session_cookies(&state, &out.refresh_token)?;

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
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<(HeaderMap, Json<RefreshResponse>), AppError> {
    let meta = audit::RequestMeta::from_headers(Method::POST, "/api/auth/refresh", &headers);
    let is_web = csrf::is_web_request(&headers);
    let ip = meta.ip.clone();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    if let Err(err) = csrf::enforce_csrf_if_web(&headers) {
        audit::auth_refresh_fail(&meta, "csrf_mismatch");

        return Err(err);
    }

    let refresh_token = match refresh::resolve_refresh_token(&headers, req.refresh_token) {
        Some(value) => value,
        None => {
            audit::auth_refresh_fail(&meta, "missing_refresh_token");

            return Err(AppError::Unauthorized);
        }
    };

    let access_ttl_seconds = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_ttl_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = match usecases::refresh(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.access_token_service,
        &state.crypto_adapters.refresh_token_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
        &ip,
        user_agent,
        access_ttl_seconds,
        refresh_ttl_days,
    )
    .await
    {
        Ok(value) => {
            audit::auth_refresh_success(&meta);

            value
        }
        Err(err) => {
            let reason = audit::auth_error_reason(&err);
            audit::auth_refresh_fail(&meta, reason);

            return Err(AppError::from(err));
        }
    };

    let response_headers = refresh::rotate_session_cookies(&state, &out.refresh_token)?;

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
    headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> Result<(HeaderMap, Json<LogoutResponse>), AppError> {
    let meta = audit::RequestMeta::from_headers(Method::POST, "/api/auth/logout", &headers);

    if let Err(err) = csrf::enforce_csrf_if_web(&headers) {
        audit::auth_logout_fail(&meta, "csrf_mismatch");

        return Err(err);
    }

    let refresh_token = match refresh::resolve_refresh_token(&headers, req.refresh_token) {
        Some(value) => value,
        None => {
            audit::auth_logout_fail(&meta, "missing_refresh_token");

            return Err(AppError::Unauthorized);
        }
    };

    if let Err(err) = usecases::logout(
        &state.crypto_adapters.refresh_token_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
    )
    .await
    {
        let reason = audit::auth_error_reason(&err);
        audit::auth_logout_fail(&meta, reason);

        return Err(AppError::from(err));
    }

    audit::auth_logout_success(&meta);

    let response_headers = cookies::refresh::clear_session_cookies(&state)?;

    Ok((response_headers, Json(LogoutResponse {})))
}

pub async fn csrf(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<serde_json::Value>), AppError> {
    let meta = audit::RequestMeta::from_headers(Method::GET, "/api/auth/csrf", &headers);
    let response_headers = csrf::issue_csrf_cookie(&state)?;

    audit::auth_csrf_issue(&meta);

    Ok((response_headers, Json(serde_json::json!({}))))
}
