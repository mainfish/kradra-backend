use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct SlowdownConfig {
    pub enabled: bool,
    pub start_after_failures: u32,
    pub step_delay_ms: u64,
    pub max_delay_ms: u64,
    pub window: Duration,
    pub entry_ttl: Duration,
    pub cleanup_every_n: u64,
}

impl SlowdownConfig {
    pub fn from_env() -> Self {
        let enabled = std::env::var("AUTH_SLOWDOWN_ENABLED")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);

        let start_after_failures = std::env::var("AUTH_SLOWDOWN_START_AFTER")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        let step_delay_ms = std::env::var("AUTH_SLOWDOWN_STEP_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(200);

        let max_delay_ms = std::env::var("AUTH_SLOWDOWN_MAX_DELAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2000);

        let window_seconds = std::env::var("AUTH_SLOWDOWN_WINDOW_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(15 * 60);

        let entry_ttl_seconds = std::env::var("AUTH_SLOWDOWN_ENTRY_TTL_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60 * 60);

        let cleanup_every_n = std::env::var("AUTH_SLOWDOWN_CLEANUP_EVERY_N")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(200);

        Self {
            enabled,
            start_after_failures: start_after_failures.max(1),
            step_delay_ms: step_delay_ms.max(1),
            max_delay_ms: max_delay_ms.max(step_delay_ms.max(1)),
            window: Duration::from_secs(window_seconds.max(30)),
            entry_ttl: Duration::from_secs(entry_ttl_seconds.max(window_seconds.max(30))),
            cleanup_every_n: cleanup_every_n.max(1),
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    failures: u32,
    last_failure: Instant,
}

#[derive(Debug)]
pub struct LoginSlowdown {
    cfg: SlowdownConfig,
    entries: Mutex<HashMap<String, Entry>>,
    checks_counter: AtomicU64,
}

impl LoginSlowdown {
    pub fn from_env() -> Self {
        Self::new(SlowdownConfig::from_env())
    }

    pub fn new(cfg: SlowdownConfig) -> Self {
        Self {
            cfg,
            entries: Mutex::new(HashMap::new()),
            checks_counter: AtomicU64::new(0),
        }
    }

    fn key(ip: &str, username: &str) -> String {
        format!("ip:{ip}|user:{}", username.trim().to_lowercase())
    }

    async fn maybe_cleanup(&self, now: Instant) {
        let current_checks = self.checks_counter.fetch_add(1, Ordering::Relaxed) + 1;

        if current_checks % self.cfg.cleanup_every_n != 0 {
            return;
        }

        let mut entries = self.entries.lock().await;
        let ttl = self.cfg.entry_ttl;

        entries.retain(|_, entry| now.duration_since(entry.last_failure) < ttl);
    }

    pub async fn maybe_delay(&self, ip: &str, username: &str) {
        if !self.cfg.enabled {
            return;
        }

        let now = Instant::now();
        self.maybe_cleanup(now).await;

        let key = Self::key(ip, username);

        let delay_ms = {
            let entries = self.entries.lock().await;

            let entry = match entries.get(&key) {
                Some(value) => value,
                None => return,
            };

            if now.duration_since(entry.last_failure) > self.cfg.window {
                return;
            }

            if entry.failures < self.cfg.start_after_failures {
                return;
            }

            let extra_failures = entry.failures - self.cfg.start_after_failures + 1;
            let computed = extra_failures as u64 * self.cfg.step_delay_ms;

            computed.min(self.cfg.max_delay_ms)
        };

        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    pub async fn record_failure(&self, ip: &str, username: &str) {
        if !self.cfg.enabled {
            return;
        }

        let now = Instant::now();
        self.maybe_cleanup(now).await;

        let key = Self::key(ip, username);

        let mut entries = self.entries.lock().await;

        let entry = entries.entry(key).or_insert(Entry {
            failures: 0,
            last_failure: now,
        });

        if now.duration_since(entry.last_failure) > self.cfg.window {
            entry.failures = 0;
        }

        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure = now;
    }

    pub async fn reset(&self, ip: &str, username: &str) {
        let key = Self::key(ip, username);

        let mut entries = self.entries.lock().await;
        entries.remove(&key);
    }
}
