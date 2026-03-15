use sqlx::{PgPool, Row, types::time::OffsetDateTime};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::models::{AuthUser, Role, User};
use kradra_core::auth::ports::UserRepo;

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

    /// Returns true only when lockout transitions from unlocked -> locked (first time).
    pub async fn record_login_failure(
        &self,
        user_id: &str,
        max_failures: i32,
        lockout_seconds: i64,
    ) -> Result<bool, AuthError> {
        let row = sqlx::query(
            r#"
        WITH prev AS (
            SELECT failed_login_attempts, locked_until
            FROM users
            WHERE id = ($1)::uuid
        ),
        upd AS (
            UPDATE users
            SET failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE
                    WHEN failed_login_attempts + 1 >= $2
                         AND (locked_until IS NULL OR locked_until <= NOW())
                        THEN NOW() + ($3 * INTERVAL '1 second')
                    ELSE locked_until
                END
            WHERE id = ($1)::uuid
            RETURNING failed_login_attempts, locked_until
        )
        SELECT
            (
                (prev.locked_until IS NULL OR prev.locked_until <= NOW())
                AND upd.failed_login_attempts >= $2
                AND upd.locked_until IS NOT NULL
            ) AS triggered
        FROM prev, upd
        "#,
        )
        .bind(user_id)
        .bind(max_failures)
        .bind(lockout_seconds)
        .fetch_one(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let triggered: bool = row.try_get("triggered").map_err(|_| AuthError::Internal)?;

        Ok(triggered)
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

    pub async fn set_role_by_username(&self, username: &str, role: &str) -> Result<u64, AuthError> {
        let result = sqlx::query(
            r#"
            UPDATE users
            SET role = $2
            WHERE username = $1
            "#,
        )
        .bind(username)
        .bind(role)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(result.rows_affected())
    }

    pub async fn users_list(&self) -> Result<Vec<User>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT id::text as id, username, password_hash, role, is_active, created_at::text as created_at
            FROM users
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let mut users = Vec::with_capacity(rows.len());

        for row in rows {
            let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
            let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
            let password_hash: String = row
                .try_get("password_hash")
                .map_err(|_| AuthError::Internal)?;
            let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;
            let role = Role::try_from(role_str.as_str()).map_err(|_| AuthError::Internal)?;
            let is_active: bool = row.try_get("is_active").map_err(|_| AuthError::Internal)?;
            let created_at: String = row.try_get("created_at").map_err(|_| AuthError::Internal)?;

            users.push(User {
                id,
                username,
                password_hash,
                role,
                is_active,
                created_at,
            });
        }

        Ok(users)
    }
}

impl UserRepo for PgUserRepo {
    async fn find_by_username(&self, username: &str) -> Result<User, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text as id, username, password_hash, role, is_active, created_at::text as created_at
            FROM users
            WHERE username = $1
            "#,
        )
        .bind(username)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Err(AuthError::UserNotFound);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|_| AuthError::Internal)?;
        let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| AuthError::Internal)?;
        let is_active: bool = row.try_get("is_active").map_err(|_| AuthError::Internal)?;
        let created_at: String = row.try_get("created_at").map_err(|_| AuthError::Internal)?;

        Ok(User {
            id,
            username,
            password_hash,
            role,
            is_active,
            created_at,
        })
    }

    async fn find_by_id(&self, user_id: &str) -> Result<User, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT id::text as id, username, password_hash, role, is_active, created_at::text as created_at
            FROM users
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Err(AuthError::UserNotFound);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let username: String = row.try_get("username").map_err(|_| AuthError::Internal)?;
        let password_hash: String = row
            .try_get("password_hash")
            .map_err(|_| AuthError::Internal)?;
        let role_str: String = row.try_get("role").map_err(|_| AuthError::Internal)?;
        let role = Role::try_from(role_str.as_str()).map_err(|_| AuthError::Internal)?;
        let is_active: bool = row.try_get("is_active").map_err(|_| AuthError::Internal)?;
        let created_at: String = row.try_get("created_at").map_err(|_| AuthError::Internal)?;

        Ok(User {
            id,
            username,
            password_hash,
            role,
            is_active,
            created_at,
        })
    }

    async fn create_user(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<AuthUser, AuthError> {
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
        let role = Role::try_from(role_str.as_str()).map_err(|_| AuthError::Internal)?;

        Ok(AuthUser { id, username, role })
    }
}
