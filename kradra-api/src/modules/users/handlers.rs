use axum::Json;

use kradra_core::auth::types::AuthUser;

use super::dto::{MeResponse, MeUser};

pub async fn me(user: AuthUser) -> Result<Json<MeResponse>, crate::error::AppError> {
    Ok(Json(MeResponse {
        user: MeUser {
            id: user.id,
            username: user.username,
            role: user.role.to_string(),
        },
    }))
}
