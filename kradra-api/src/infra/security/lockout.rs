use kradra_core::auth::errors::AuthError;

use crate::infra::db::user_repo::PgUserRepo;

#[derive(Debug, Clone)]
pub struct LockoutPolicy {
    pub max_failures: i32,
    pub lockout_seconds: i64,
}

impl LockoutPolicy {
    pub fn from_env() -> Self {
        let max_failures = std::env::var("AUTH_LOCKOUT_MAX_FAILURES")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(10);

        let lockout_seconds = std::env::var("AUTH_LOCKOUT_SECONDS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(900);

        Self {
            max_failures,
            lockout_seconds,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LockoutCheck {
    pub user_id: Option<String>,
    pub is_locked: bool,
}

#[derive(Debug, Clone)]
pub struct LockoutService {
    policy: LockoutPolicy,
}

impl LockoutService {
    pub fn from_env() -> Self {
        Self {
            policy: LockoutPolicy::from_env(),
        }
    }

    pub async fn check(
        &self,
        user_repo: &PgUserRepo,
        username: &str,
    ) -> Result<LockoutCheck, AuthError> {
        let lockout_state = user_repo.get_lockout_state_by_username(username).await?;

        let Some(state_row) = lockout_state else {
            return Ok(LockoutCheck {
                user_id: None,
                is_locked: false,
            });
        };

        Ok(LockoutCheck {
            user_id: Some(state_row.id.clone()),
            is_locked: PgUserRepo::is_locked_now(&state_row),
        })
    }

    pub async fn record_failure(
        &self,
        user_repo: &PgUserRepo,
        user_id: &str,
    ) -> Result<bool, AuthError> {
        user_repo
            .record_login_failure(
                user_id,
                self.policy.max_failures,
                self.policy.lockout_seconds,
            )
            .await
    }

    pub async fn reset_on_success(
        &self,
        user_repo: &PgUserRepo,
        user_id: &str,
    ) -> Result<(), AuthError> {
        user_repo.reset_login_failures(user_id).await
    }
}
