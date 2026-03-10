use axum::http::{HeaderMap, Method};

#[derive(Debug, Clone)]
pub struct RequestMeta {
    pub method: Method,
    pub path: String,
    pub ip: String,
    pub user_agent: String,
}

impl RequestMeta {
    pub fn from_headers(method: Method, path: impl Into<String>, headers: &HeaderMap) -> Self {
        Self {
            method,
            path: path.into(),
            ip: client_ip(headers),
            user_agent: user_agent(headers),
        }
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    "unknown".to_string()
}

fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---- Auth audit events ----

pub fn auth_register_success(meta: &RequestMeta, username: &str, user_id: &str) {
    tracing::info!(
        event = "auth.register.success",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        username = %username,
        user_id = %user_id
    );
}

pub fn auth_register_fail(meta: &RequestMeta, username: &str, reason: &str) {
    tracing::warn!(
        event = "auth.register.fail",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        username = %username,
        reason = %reason
    );
}

pub fn auth_login_success(meta: &RequestMeta, username: &str) {
    tracing::info!(
        event = "auth.login.success",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        username = %username
    );
}

pub fn auth_login_fail(meta: &RequestMeta, username: &str, reason: &str) {
    tracing::warn!(
        event = "auth.login.fail",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        username = %username,
        reason = %reason
    );
}

pub fn auth_refresh_success(meta: &RequestMeta) {
    tracing::info!(
        event = "auth.refresh.success",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent
    );
}

pub fn auth_refresh_fail(meta: &RequestMeta, reason: &str) {
    tracing::warn!(
        event = "auth.refresh.fail",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        reason = %reason
    );
}

pub fn auth_logout_success(meta: &RequestMeta) {
    tracing::info!(
        event = "auth.logout.success",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent
    );
}

pub fn auth_logout_fail(meta: &RequestMeta, reason: &str) {
    tracing::warn!(
        event = "auth.logout.fail",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent,
        reason = %reason
    );
}

pub fn auth_csrf_issue(meta: &RequestMeta) {
    tracing::info!(
        event = "auth.csrf.issue",
        method = ?meta.method,
        path = %meta.path,
        ip = %meta.ip,
        ua = %meta.user_agent
    );
}
