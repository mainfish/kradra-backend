use sqlx::{PgPool, Row};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::ports::{RefreshTokenRecord, RefreshTokenStore};

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
    ) -> Result<String, AuthError> {
        let row = sqlx::query(
            r#"
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (($1)::uuid, $2, to_timestamp($3))
            RETURNING id::text as id
            "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_unix)
        .fetch_one(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        Ok(id)
    }

    async fn get_by_hash(&self, token_hash: &str) -> Result<Option<RefreshTokenRecord>, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT
              id::text as id,
              user_id::text as user_id,
              revoked_at IS NOT NULL as is_revoked,
              replaced_by IS NOT NULL as is_replaced,
              (extract(epoch from expires_at))::bigint as expires_unix
            FROM refresh_tokens
            WHERE token_hash = $1
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let id: String = row.try_get("id").map_err(|_| AuthError::Internal)?;
        let user_id: String = row.try_get("user_id").map_err(|_| AuthError::Internal)?;
        let is_revoked: bool = row.try_get("is_revoked").map_err(|_| AuthError::Internal)?;
        let is_replaced: bool = row
            .try_get("is_replaced")
            .map_err(|_| AuthError::Internal)?;
        let expires_unix: i64 = row
            .try_get("expires_unix")
            .map_err(|_| AuthError::Internal)?;

        Ok(Some(RefreshTokenRecord {
            id,
            user_id,
            is_revoked,
            is_replaced,
            expires_unix,
        }))
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

    async fn revoke_and_link(&self, old_id: &str, new_id: &str) -> Result<(), AuthError> {
        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET revoked_at = now(), replaced_by = ($2)::uuid
            WHERE id = ($1)::uuid
            "#,
        )
        .bind(old_id)
        .bind(new_id)
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
}
