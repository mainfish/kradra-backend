use axum::http::{HeaderMap, HeaderValue, header};

use crate::error::AppError;
use crate::state::AppState;

use super::csrf;

pub const REFRESH_COOKIE_NAME: &str = "refresh_token";

/// Cookie configuration (держим в refresh.rs, чтобы mod.rs был пустым).
#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub secure: bool,
    pub samesite: String,
    pub domain: Option<String>,
    pub max_age_seconds: i64,
}

impl CookieConfig {
    pub fn from_state(state: &AppState) -> Self {
        let auth = &state.crypto_adapters.auth_config;
        Self {
            secure: auth.cookie_secure,
            samesite: auth.cookie_samesite.clone(),
            domain: auth.cookie_domain.clone(),
            max_age_seconds: auth.refresh_ttl_days * 24 * 60 * 60,
        }
    }
}

/// Parse a single cookie value from the Cookie header.
pub(crate) fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw_cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;

    for cookie_part in raw_cookie_header.split(';') {
        let trimmed_part = cookie_part.trim();
        if let Some((key, value)) = trimmed_part.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }

    None
}

/// Read a request header as string.
pub(crate) fn get_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Attach a Set-Cookie header value. Uses `append` if Set-Cookie already exists.
pub(crate) fn push_set_cookie(headers: &mut HeaderMap, cookie: String) -> Result<(), AppError> {
    let header_value = HeaderValue::from_str(&cookie).map_err(|_| AppError::Internal)?;

    if headers.contains_key(header::SET_COOKIE) {
        headers.append(header::SET_COOKIE, header_value);
    } else {
        headers.insert(header::SET_COOKIE, header_value);
    }

    Ok(())
}

fn build_refresh_cookie(cfg: &CookieConfig, value: &str, max_age_seconds: i64) -> String {
    let mut cookie_string = format!(
        "{name}={value}; HttpOnly; Path=/; Max-Age={max_age}",
        name = REFRESH_COOKIE_NAME,
        value = value,
        max_age = max_age_seconds.max(0)
    );

    let same_site = cfg.samesite.trim();
    if !same_site.is_empty() {
        cookie_string.push_str("; SameSite=");
        cookie_string.push_str(same_site);
    }

    if let Some(domain) = &cfg.domain {
        let domain_trimmed = domain.trim();
        if !domain_trimmed.is_empty() {
            cookie_string.push_str("; Domain=");
            cookie_string.push_str(domain_trimmed);
        }
    }

    if cfg.secure {
        cookie_string.push_str("; Secure");
    }

    cookie_string
}

pub fn read_refresh_from_cookie(headers: &HeaderMap) -> Option<String> {
    get_cookie(headers, REFRESH_COOKIE_NAME)
}

pub fn set_refresh_cookie(
    headers: &mut HeaderMap,
    cfg: &CookieConfig,
    refresh_plain: &str,
) -> Result<(), AppError> {
    let cookie_string = build_refresh_cookie(cfg, refresh_plain, cfg.max_age_seconds);
    push_set_cookie(headers, cookie_string)
}

pub fn clear_refresh_cookie(headers: &mut HeaderMap, cfg: &CookieConfig) -> Result<(), AppError> {
    let cookie_string = build_refresh_cookie(cfg, "", 0);
    push_set_cookie(headers, cookie_string)
}

// ---- Session-level helpers (keep auth handlers clean) ----

// ---- Session-level helpers (keep auth handlers clean) ----

pub fn issue_session_cookies(state: &AppState, refresh_plain: &str) -> Result<HeaderMap, AppError> {
    let cookie_config = CookieConfig::from_state(state);
    let csrf_token = csrf::generate_csrf_token();

    let mut response_headers = HeaderMap::new();
    set_refresh_cookie(&mut response_headers, &cookie_config, refresh_plain)?;
    csrf::set_csrf_cookie(&mut response_headers, &cookie_config, &csrf_token)?;

    Ok(response_headers)
}

pub fn rotate_session_cookies(
    state: &AppState,
    refresh_plain: &str,
) -> Result<HeaderMap, AppError> {
    issue_session_cookies(state, refresh_plain)
}

pub fn clear_session_cookies(state: &AppState) -> Result<HeaderMap, AppError> {
    let cookie_config = CookieConfig::from_state(state);

    let mut response_headers = HeaderMap::new();
    clear_refresh_cookie(&mut response_headers, &cookie_config)?;
    csrf::clear_csrf_cookie(&mut response_headers, &cookie_config)?;

    Ok(response_headers)
}

pub fn resolve_refresh_token(
    request_headers: &HeaderMap,
    body_refresh_token: Option<String>,
) -> Option<String> {
    body_refresh_token.or_else(|| read_refresh_from_cookie(request_headers))
}
