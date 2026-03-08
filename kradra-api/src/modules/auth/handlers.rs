use axum::{
    Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
};

use super::dto::{
    LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, RefreshRequest, RefreshResponse,
    RegisterRequest, RegisterResponse, RegisterUser,
};
use crate::{error::AppError, state::AppState};

const REFRESH_COOKIE_NAME: &str = "refresh_token";

fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn build_refresh_set_cookie(state: &AppState, value: &str, max_age_seconds: i64) -> String {
    let mut s = format!(
        "{name}={value}; HttpOnly; Path=/; Max-Age={max_age}",
        name = REFRESH_COOKIE_NAME,
        value = value,
        max_age = max_age_seconds.max(0)
    );

    // SameSite
    let ss = state.crypto_adapters.auth_config.cookie_samesite.trim();
    if !ss.is_empty() {
        s.push_str("; SameSite=");
        s.push_str(ss);
    }

    // Domain (optional)
    if let Some(domain) = &state.crypto_adapters.auth_config.cookie_domain {
        let d = domain.trim();
        if !d.is_empty() {
            s.push_str("; Domain=");
            s.push_str(d);
        }
    }

    // Secure (recommended in prod)
    if state.crypto_adapters.auth_config.cookie_secure {
        s.push_str("; Secure");
    }

    s
}

fn set_cookie_headers(state: &AppState, refresh_plain: &str) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    let max_age = state.crypto_adapters.auth_config.refresh_ttl_days * 24 * 60 * 60;
    let cookie = build_refresh_set_cookie(state, refresh_plain, max_age);

    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| AppError::Internal)?,
    );
    Ok(headers)
}

fn clear_cookie_headers(state: &AppState) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    let cookie = build_refresh_set_cookie(state, "", 0);

    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| AppError::Internal)?,
    );
    Ok(headers)
}

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
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), AppError> {
    let is_web = headers.get(header::ORIGIN).is_some();

    let ttl = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = kradra_core::auth::usecases::login(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.password_hasher,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &req.username,
        &req.password,
        ttl,
        refresh_days,
    )
    .await
    .map_err(AppError::from)?;

    // always set cookie (web); CLI can ignore
    let set_headers = set_cookie_headers(&state, &out.refresh_token)?;

    Ok((
        set_headers,
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
    let is_web = headers.get(header::ORIGIN).is_some();

    let refresh_token = req
        .refresh_token
        .or_else(|| get_cookie(&headers, REFRESH_COOKIE_NAME))
        .ok_or(AppError::Unauthorized)?;

    let ttl = state.crypto_adapters.auth_config.access_ttl_seconds;
    let refresh_days = state.crypto_adapters.auth_config.refresh_ttl_days;

    let out = kradra_core::auth::usecases::refresh(
        &state.db_adapters.user_repo,
        &state.crypto_adapters.token_issuer,
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
        ttl,
        refresh_days,
    )
    .await
    .map_err(AppError::from)?;

    // rotate cookie
    let set_headers = set_cookie_headers(&state, &out.refresh_token)?;

    Ok((
        set_headers,
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
    let refresh_token = req
        .refresh_token
        .or_else(|| get_cookie(&headers, REFRESH_COOKIE_NAME))
        .ok_or(AppError::Unauthorized)?;

    kradra_core::auth::usecases::logout(
        &state.crypto_adapters.refresh_service,
        &state.db_adapters.refresh_token_store,
        &refresh_token,
    )
    .await
    .map_err(AppError::from)?;

    let cleared = clear_cookie_headers(&state)?;
    Ok((cleared, Json(LogoutResponse {})))
}
