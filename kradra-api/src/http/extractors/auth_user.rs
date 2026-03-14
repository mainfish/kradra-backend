use axum::{
    extract::FromRequestParts,
    http::{header::AUTHORIZATION, request::Parts},
};

use crate::{error::AppError, state::AppState};

use kradra_core::auth::errors::AuthError;
use kradra_core::auth::models::{AuthUser, Role};
use kradra_core::auth::ports::AccessTokenCodec;

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Authorization: Bearer <token>
        let auth = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .ok_or(AppError::Unauthorized)?;

        let user = state
            .crypto_adapters
            .access_token_service
            .verify(token)
            .map_err(AppError::from)?;

        Ok(user)
    }
}

pub fn require_admin(user: &AuthUser) -> Result<(), AppError> {
    if user.role == Role::Admin {
        return Ok(());
    }

    Err(AppError::from(AuthError::Forbidden))
}
