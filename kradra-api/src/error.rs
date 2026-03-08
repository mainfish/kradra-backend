use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;
use std::fmt;

use kradra_core::auth::errors::AuthError;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    BadRequest(String),
    ServiceUnavailable(String),
    Internal,
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        AppError::BadRequest(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        AppError::Conflict(message.into())
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        AppError::ServiceUnavailable(message.into())
    }

    pub fn unauthorized() -> Self {
        AppError::Unauthorized
    }

    pub fn forbidden() -> Self {
        AppError::Forbidden
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Unauthorized => write!(f, "unauthorized"),
            AppError::Forbidden => write!(f, "forbidden"),
            AppError::NotFound => write!(f, "not found"),
            AppError::Conflict(message) => write!(f, "{message}"),
            AppError::BadRequest(message) => write!(f, "{message}"),
            AppError::ServiceUnavailable(message) => write!(f, "{message}"),
            AppError::Internal => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials => AppError::Unauthorized,
            AuthError::BadRequest(msg) => AppError::BadRequest(msg),
            AuthError::UserAlreadyExists => AppError::Conflict(err.to_string()),
            AuthError::Unauthorized => AppError::Unauthorized,
            AuthError::Forbidden => AppError::Forbidden,
            AuthError::TokenInvalid => AppError::Unauthorized,
            AuthError::TokenExpired => AppError::Unauthorized,
            AuthError::Internal => AppError::Internal,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            AppError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            AppError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            AppError::ServiceUnavailable(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable")
            }
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };

        let body = Json(json!({
            "error": { "code": code, "message": self.to_string() }
        }));

        (status, body).into_response()
    }
}
