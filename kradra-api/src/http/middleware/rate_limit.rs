use axum::body::Body;
use axum::http::{HeaderName, Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::error::AppError;

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub window: Duration,
    pub max_requests: u32,
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        let window_seconds = std::env::var("AUTH_RATE_LIMIT_WINDOW_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        let max_requests = std::env::var("AUTH_RATE_LIMIT_MAX")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(10);

        Self {
            window: Duration::from_secs(window_seconds.max(1)),
            max_requests: max_requests.max(1),
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
}

impl RateLimiter {
    pub fn new(cfg: RateLimitConfig) -> Self {
        Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Ok(()) если можно, Err(retry_after_seconds) если лимит.
    pub async fn check(&self, key: &str) -> Result<(), u64> {
        let mut entries = self.entries.lock().await;
        let now = Instant::now();

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

fn client_key_from_headers(req: &Request<Body>) -> String {
    // Prefer proxy headers (nginx) when present.
    if let Some(forwarded_for) = req
        .headers()
        .get(HeaderName::from_static("x-forwarded-for"))
    {
        if let Ok(value) = forwarded_for.to_str() {
            // X-Forwarded-For may be a list.
            if let Some(first) = value.split(',').next() {
                let ip = first.trim();
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

pub async fn auth_rate_limit(
    axum::extract::Extension(limiter): axum::extract::Extension<Arc<RateLimiter>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    if !is_rate_limited_path(&req) {
        return Ok(next.run(req).await);
    }

    let key = client_key_from_headers(&req);

    match limiter.check(&key).await {
        Ok(()) => Ok(next.run(req).await),
        Err(retry_after_seconds) => Err(AppError::too_many_requests(retry_after_seconds)),
    }
}
