use kradra_core::auth::errors::AuthError;
use kradra_core::auth::ports::AppSettingsStore;
use sqlx::{PgPool, Row};

#[derive(Clone)]
pub struct PgAppSettingsStore {
    db: PgPool,
}

impl PgAppSettingsStore {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

impl AppSettingsStore for PgAppSettingsStore {
    async fn get_registration_enabled(&self) -> Result<bool, AuthError> {
        let row = sqlx::query(
            r#"
            SELECT value
            FROM app_settings
            WHERE key = 'registration_enabled'
            "#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        let Some(row) = row else {
            return Ok(true);
        };

        let value: String = row.try_get("value").map_err(|_| AuthError::Internal)?;

        Ok(matches!(
            value.as_str(),
            "1" | "true" | "TRUE" | "yes" | "YES"
        ))
    }

    async fn set_registration_enabled(&self, enabled: bool) -> Result<(), AuthError> {
        let value = if enabled { "true" } else { "false" };

        sqlx::query(
            r#"
            INSERT INTO app_settings (key, value, updated_at)
            VALUES ('registration_enabled', $1, now())
            ON CONFLICT (key)
            DO UPDATE SET
                value = EXCLUDED.value,
                updated_at = now()
            "#,
        )
        .bind(value)
        .execute(&self.db)
        .await
        .map_err(|_| AuthError::Internal)?;

        Ok(())
    }
}
