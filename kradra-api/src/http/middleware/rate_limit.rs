use axum::body::{Body, Bytes, to_bytes};
use axum::http::{HeaderName, Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::error::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitKeyMode {
    IpOnly,
    IpUsername,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub window: Duration,
    pub max_requests: u32,
    pub body_limit_bytes: usize,
    pub key_mode: RateLimitKeyMode,
    pub entry_ttl: Duration,
    pub cleanup_every_n_checks: u64,
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        let window_seconds = std::env::var("AUTH_RATE_LIMIT_WINDOW_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(60);
        let max_requests = std::env::var("AUTH_RATE_LIMIT_MAX")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(10);
        let body_limit_bytes = std::env::var("AUTH_RATE_LIMIT_BODY_LIMIT_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(8 * 1024);
        let entry_ttl_seconds = std::env::var("AUTH_RATE_LIMIT_ENTRY_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(600);
        let cleanup_every_n_checks = std::env::var("AUTH_RATE_LIMIT_CLEANUP_EVERY_N")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(200);
        let key_mode = match std::env::var("AUTH_RATE_LIMIT_KEY_MODE")
            .unwrap_or_else(|_| "ip_username".to_string())
            .trim()
            .to_lowercase()
            .as_str()
        {
            "ip_only" => RateLimitKeyMode::IpOnly,
            _ => RateLimitKeyMode::IpUsername,
        };

        Self {
            window: Duration::from_secs(window_seconds.max(1)),
            max_requests: max_requests.max(1),
            body_limit_bytes: body_limit_bytes.max(1024),
            key_mode: key_mode,
            entry_ttl: Duration::from_secs(entry_ttl_seconds.max(window_seconds.max(1))),
            cleanup_every_n_checks: cleanup_every_n_checks.max(1),
        }
    }
}

#[derive(Debug)]
struct Entry {
    window_start: Instant,
    count: u32,
}

#[derive(Debug)]
pub struct RateLimiter {
    cfg: RateLimitConfig,
    entries: Mutex<HashMap<String, Entry>>,
    checks_counter: AtomicU64,
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
            checks_counter: AtomicU64::new(0),
        }
    }

    pub fn cfg(&self) -> &RateLimitConfig {
        &self.cfg
    }

    async fn maybe_cleanup(&self, now: Instant) {
        let current_checks = self.checks_counter.fetch_add(1, Ordering::Relaxed) + 1;

        if current_checks % self.cfg.cleanup_every_n_checks != 0 {
            return;
        }

        let mut entries = self.entries.lock().await;
        let entry_ttl = self.cfg.entry_ttl;

        entries.retain(|_, entry| now.duration_since(entry.window_start) < entry_ttl);
    }

    pub async fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();

        self.maybe_cleanup(now).await;

        let mut entries = self.entries.lock().await;

        let entry = entries.entry(key.to_string()).or_insert(Entry {
            window_start: now,
            count: 0,
        });

        if now.duration_since(entry.window_start) >= self.cfg.window {
            entry.window_start = now;
            entry.count = 0;
        }

        if entry.count >= self.cfg.max_requests {
            let elapsed = now.duration_since(entry.window_start);
            let retry_after_seconds = self.cfg.window.saturating_sub(elapsed).as_secs().max(1);

            return Err(retry_after_seconds);
        }

        entry.count += 1;
        Ok(())
    }
}

fn is_rate_limited_path(req: &Request<Body>) -> bool {
    if req.method() != Method::POST {
        return false;
    }

    matches!(req.uri().path(), "/api/auth/login" | "/api/auth/register")
}

fn client_ip_key(req: &Request<Body>) -> String {
    if let Some(forwarded_for) = req
        .headers()
        .get(HeaderName::from_static("x-forwarded-for"))
    {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(first_ip) = value.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return format!("ip:{ip}");
                }
            }
        }
    }

    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_raw) = real_ip.to_str() {
            let ip = ip_raw.trim();
            if !ip.is_empty() {
                return format!("ip:{ip}");
            }
        }
    }

    "ip:unknown".to_string()
}

fn normalize_username(username: &str) -> Option<String> {
    let normalized = username.trim().to_lowercase();

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn extract_username_from_json(body_bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body_bytes).ok()?;
    let username = value.get("username")?.as_str()?;
    normalize_username(username)
}

fn build_rate_limit_key(cfg: &RateLimitConfig, ip_key: String, username: Option<String>) -> String {
    match cfg.key_mode {
        RateLimitKeyMode::IpOnly => ip_key,
        RateLimitKeyMode::IpUsername => match username {
            Some(user) => format!("{ip_key}|user:{user}"),
            None => ip_key,
        },
    }
}

pub async fn auth_rate_limit(
    axum::extract::Extension(limiter): axum::extract::Extension<Arc<RateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    if !is_rate_limited_path(&req) {
        return Ok(next.run(req).await);
    }

    let (parts, body) = req.into_parts();

    let body_bytes: Bytes = to_bytes(body, limiter.cfg().body_limit_bytes)
        .await
        .map_err(|_| AppError::bad_request("request body is too large"))?;

    let username = extract_username_from_json(&body_bytes);

    let request_for_next = Request::from_parts(parts, Body::from(body_bytes.clone()));

    let ip_key = client_ip_key(&request_for_next);
    let rate_limit_key = build_rate_limit_key(limiter.cfg(), ip_key, username);

    match limiter.check(&rate_limit_key).await {
        Ok(()) => Ok(next.run(request_for_next).await),
        Err(retry_after_seconds) => Err(AppError::too_many_requests(retry_after_seconds)),
    }
}
