use sqlx::{PgPool, Row};

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
