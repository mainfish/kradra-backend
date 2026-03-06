use axum::{Router, routing::post};

use crate::state::AppState;

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/auth/register", post(handlers::register))
        .route("/api/auth/login", post(handlers::login))
        .route("/api/auth/refresh", post(handlers::refresh))
        .route("/api/auth/logout", post(handlers::logout))
}
