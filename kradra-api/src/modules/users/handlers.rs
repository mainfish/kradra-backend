use axum::{Json, extract::State, http::HeaderMap, http::header::AUTHORIZATION};

use crate::{error::AppError, state::AppState};

use super::dto::{MeResponse, MeUser};

pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, AppError> {
    // 1) достаём Bearer токен
    let auth = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let token = auth
        .strip_prefix("Bearer ")
        .or_else(|| auth.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?;

    // 2) валидируем JWT (подпись + exp)
    let claims = crate::crypto::tokens::decode_access_token(token, &state.auth.jwt_secret)
        .map_err(|_| AppError::Unauthorized)?;

    // 3) возвращаем инфу о текущем пользователе (пока stub, но auth реальный)
    Ok(Json(MeResponse {
        user: MeUser {
            id: claims.sub,
            username: claims.username,
            role: claims.role,
        },
    }))
}
