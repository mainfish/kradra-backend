use std::time::{SystemTime, UNIX_EPOCH};

use sqlx::{PgPool, Row};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::models::UserSession;
use kradra_core::auth::ports::RefreshTokenStore;

#[derive(Clone)]
pub struct PgRefreshTokenStore {
    db: PgPool,
}

impl PgRefreshTokenStore {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

impl RefreshTokenStore for PgRefreshTokenStore {
    async fn insert_refresh_returning_id(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_unix: i64,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<String, AuthError> {
        let row = sqlx::query(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip, user_agent)
            VALUES (($1)::uuid, $2, to_timestamp($3), $4, $5)
            RETURNING id::text as id
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_unix)
        .bind(ip)
        .bind(user_agent)
        .fetch_one(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;

        Ok(id)
    }

    async fn get_by_hash(&self, token_hash: &str) -> Result<UserSession, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT
            id::text as id,
            user_id::text as user_id,
            ip,
            user_agent,
            revoked_at IS NOT NULL as is_revoked,
            replaced_by IS NOT NULL as is_replaced,
            (extract(epoch from expires_at))::bigint as expires_unix
            FROM refresh_tokens
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Err(AuthError::InvalidRefreshToken);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let user_id: String = row.try_get("user_id").map_err(|_| AuthError::Internal)?;
        let ip: Option<String> = row.try_get("ip").map_err(|_| AuthError::Internal)?;
        let user_agent: Option<String> =
            row.try_get("user_agent").map_err(|_| AuthError::Internal)?;
        let is_revoked: bool = row.try_get("is_revoked").map_err(|_| AuthError::Internal)?;
        let is_replaced: bool = row
            .try_get("is_replaced")
            .map_err(|_| AuthError::Internal)?;
        let expires_unix: i64 = row
            .try_get("expires_unix")
            .map_err(|_| AuthError::Internal)?;

        Ok(UserSession {
            id,
            user_id,
            ip,
            user_agent,
            is_revoked,
            is_replaced,
            expires_unix,
        })
    }

    async fn rotate_refresh_token(
        &self,
        old_token_hash: &str,
        new_token_hash: &str,
        expires_unix: i64,
        ip: &str,
        user_agent: Option<&str>,
    ) -> Result<UserSession, AuthError> {
        let mut tx = self.db.begin().await.map_err(|_| AuthError::Internal)?;

        let row = sqlx::query(
            r#"
            SELECT
            id::text as id,
            user_id::text as user_id,
            ip,
            user_agent,
            revoked_at IS NOT NULL as is_revoked,
            replaced_by IS NOT NULL as is_replaced,
            (extract(epoch from expires_at))::bigint as expires_unix
            FROM refresh_tokens
            WHERE token_hash = $1
            FOR UPDATE
            "#,
        )
        .bind(old_token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Err(AuthError::InvalidRefreshToken);
        };

        let current = UserSession {
            id: row.try_get("id").map_err(|_| AuthError::Internal)?,
            user_id: row.try_get("user_id").map_err(|_| AuthError::Internal)?,
            ip: row.try_get("ip").map_err(|_| AuthError::Internal)?,
            user_agent: row.try_get("user_agent").map_err(|_| AuthError::Internal)?,
            is_revoked: row.try_get("is_revoked").map_err(|_| AuthError::Internal)?,
            is_replaced: row
                .try_get("is_replaced")
                .map_err(|_| AuthError::Internal)?,
            expires_unix: row
                .try_get("expires_unix")
                .map_err(|_| AuthError::Internal)?,
        };

        if current.is_revoked || current.is_replaced {
            return Err(AuthError::InvalidRefreshToken);
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::Internal)?
            .as_secs() as i64;

        if current.expires_unix <= now_unix {
            return Err(AuthError::TokenExpired);
        }

        let new_row = sqlx::query(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at, ip, user_agent)
            VALUES (($1)::uuid, $2, to_timestamp($3), $4, $5)
            RETURNING id::text as id
            "#,
        )
        .bind(&current.user_id)
        .bind(new_token_hash)
        .bind(expires_unix)
        .bind(ip)
        .bind(user_agent)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;

        let new_id: String = new_row.try_get("id").map_err(|_| AuthError::Internal)?;

        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = now(), replaced_by = ($2)::uuid
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(&current.id)
        .bind(&new_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| AuthError::Internal)?;

        tx.commit().await.map_err(|_| AuthError::Internal)?;

        Ok(UserSession {
            id: new_id,
            user_id: current.user_id,
            ip: Some(ip.to_string()),
            user_agent: user_agent.map(str::to_string),
            is_revoked: false,
            is_replaced: false,
            expires_unix,
        })
    }

    async fn revoke_all_active_for_user(&self, user_id: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = now()
            WHERE user_id = ($1)::uuid
            AND revoked_at IS NULL
            "#,
        )
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(())
    }

    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = now()
            WHERE token_hash = $1
            AND revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(())
    }

    async fn list_sessions_for_user(&self, user_id: &str) -> Result<Vec<UserSession>, AuthError> {
        let rows = sqlx::query(
            r#"
            SELECT
            id::text as id,
            user_id::text as user_id,
            ip,
            user_agent,
            revoked_at IS NOT NULL as is_revoked,
            replaced_by IS NOT NULL as is_replaced,
            (extract(epoch from expires_at))::bigint as expires_unix
            FROM refresh_tokens
            WHERE user_id = ($1)::uuid
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        rows.into_iter()
            .map(|row| {
                Ok(UserSession {
                    id: row.try_get("id").map_err(|_| AuthError::Internal)?,
                    user_id: row.try_get("user_id").map_err(|_| AuthError::Internal)?,
                    ip: row.try_get("ip").map_err(|_| AuthError::Internal)?,
                    user_agent: row.try_get("user_agent").map_err(|_| AuthError::Internal)?,
                    is_revoked: row.try_get("is_revoked").map_err(|_| AuthError::Internal)?,
                    is_replaced: row
                        .try_get("is_replaced")
                        .map_err(|_| AuthError::Internal)?,
                    expires_unix: row
                        .try_get("expires_unix")
                        .map_err(|_| AuthError::Internal)?,
                })
            })
            .collect()
    }
}
