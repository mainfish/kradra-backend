use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Unauthorized,
    NotFound,
    Conflict(String),
    BadRequest(String),
    ServiceUnavailable(String),
    Internal,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Unauthorized => write!(f, "unauthorized"),
            AppError::NotFound => write!(f, "not found"),
            AppError::BadRequest(message) => write!(f, "{message}"),
            AppError::Conflict(message) => write!(f, "{message}"),
            AppError::ServiceUnavailable(message) => write!(f, "{message}"),
            AppError::Internal => write!(f, "internal error"),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, code) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
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
