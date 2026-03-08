use axum::http::{HeaderMap, header};

use crate::error::AppError;

use super::refresh::{CookieConfig, get_cookie, get_header, push_set_cookie};

pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "x-csrf-token";

fn build_csrf_cookie(cfg: &CookieConfig, value: &str, max_age_seconds: i64) -> String {
    let mut cookie_string = format!(
        "{name}={value}; Path=/; Max-Age={max_age}",
        name = CSRF_COOKIE_NAME,
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

pub fn is_web_request(headers: &HeaderMap) -> bool {
    headers.get(header::ORIGIN).is_some()
}

pub fn generate_csrf_token() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand_core::{OsRng, RngCore};

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn set_csrf_cookie(
    headers: &mut HeaderMap,
    cfg: &CookieConfig,
    csrf: &str,
) -> Result<(), AppError> {
    let cookie_string = build_csrf_cookie(cfg, csrf, cfg.max_age_seconds);
    push_set_cookie(headers, cookie_string)
}

pub fn clear_csrf_cookie(headers: &mut HeaderMap, cfg: &CookieConfig) -> Result<(), AppError> {
    let cookie_string = build_csrf_cookie(cfg, "", 0);
    push_set_cookie(headers, cookie_string)
}

/// Enforce CSRF for web requests only (Origin present).
pub fn enforce_csrf_if_web(headers: &HeaderMap) -> Result<(), AppError> {
    if !is_web_request(headers) {
        return Ok(());
    }

    let csrf_cookie_value = get_cookie(headers, CSRF_COOKIE_NAME).ok_or(AppError::Forbidden)?;
    let csrf_header_value = get_header(headers, CSRF_HEADER_NAME).ok_or(AppError::Forbidden)?;

    if csrf_cookie_value != csrf_header_value {
        return Err(AppError::Forbidden);
    }

    Ok(())
}
