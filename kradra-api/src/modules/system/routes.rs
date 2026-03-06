use axum::{Router, routing::get};

use super::handlers;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(handlers::root))
        .route("/health", get(handlers::health))
        .route("/health/readiness", get(handlers::readiness))
        .route("/api/ping", get(handlers::ping))
}
