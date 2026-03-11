use sqlx::{PgPool, Row, types::time::OffsetDateTime};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::ports::{CreatedUserRecord, UserRecord, UserRepo};

#[derive(Clone)]
pub struct PgUserRepo {
    db: PgPool,
}

impl PgUserRepo {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[derive(Debug, Clone)]
pub struct UserLockoutState {
    pub id: String,
    pub failed_login_attempts: i32,
    pub locked_until: Option<OffsetDateTime>,
}

impl PgUserRepo {
    pub fn is_locked_now(state: &UserLockoutState) -> bool {
        match state.locked_until {
            Some(locked_until) => locked_until > OffsetDateTime::now_utc(),
            None => false,
        }
    }

    pub async fn get_lockout_state_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserLockoutState>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text as id,
                   failed_login_attempts,
                   locked_until
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let failed_login_attempts: i32 = row
            .try_get("failed_login_attempts")
            .map_err(|_| AuthError::Internal)?;
        let locked_until: Option<OffsetDateTime> = row
            .try_get("locked_until")
            .map_err(|_| AuthError::Internal)?;

        if let Some(locked_until_value) = locked_until {
            if locked_until_value <= OffsetDateTime::now_utc() {
                self.reset_login_failures(&id).await?;

                return Ok(Some(UserLockoutState {
                    id,
                    failed_login_attempts: 0,
                    locked_until: None,
                }));
            }
        }

        Ok(Some(UserLockoutState {
            id,
            failed_login_attempts,
            locked_until,
        }))
    }

    pub async fn record_login_failure(
        &self,
        user_id: &str,
        max_failures: i32,
        lockout_seconds: i64,
    ) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN failed_login_attempts + 1 >= $2 THEN NOW() + ($3 * INTERVAL '1 second')
                    ELSE locked_until
                END
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(user_id)
        .bind(max_failures)
        .bind(lockout_seconds)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(())
    }

    pub async fn reset_login_failures(&self, user_id: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE users
            SET failed_login_attempts = 0,
                locked_until = NULL
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(())
    }
}

impl UserRepo for PgUserRepo {
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text as id, username, password_hash, role, is_active
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|_| AuthError::Internal)?;
        let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;
        let is_active: bool = row.try_get("is_active").map_err(|_| AuthError::Internal)?;

        let role = kradra_core::auth::types::Role::try_from(role_str.as_str())
            .map_err(|_| AuthError::Internal)?;

        Ok(Some(UserRecord {
            id,
            username,
            password_hash,
            role,
            is_active,
        }))
    }

    async fn find_by_id(&self, user_id: &str) -> Result<Option<UserRecord>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text as id, username, password_hash, role, is_active
            FROM users
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|_| AuthError::Internal)?;
        let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;
        let is_active: bool = row.try_get("is_active").map_err(|_| AuthError::Internal)?;

        let role = kradra_core::auth::types::Role::try_from(role_str.as_str())
            .map_err(|_| AuthError::Internal)?;

        Ok(Some(UserRecord {
            id,
            username,
            password_hash,
            role,
            is_active,
        }))
    }

    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<CreatedUserRecord, AuthError> {
        let inserted = sqlx::query(
            r#"
            INSERT INTO users (username, password_hash)
            VALUES ($1, $2)
            RETURNING id::text as id, username, role
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .fetch_one(&self.db)
        .await;

        let row = match inserted {
            Ok(row) => row,
            Err(err) => {
                if let sqlx::Error::Database(db_err) = &err {
                    // unique_violation
                    if db_err.code().as_deref() == Some("23505") {
                        return Err(AuthError::UserAlreadyExists);
                    }
                }
                return Err(AuthError::Internal);
            }
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
        let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;

        let role = kradra_core::auth::types::Role::try_from(role_str.as_str())
            .map_err(|_| AuthError::Internal)?;

        Ok(CreatedUserRecord { id, username, role })
    }
}
