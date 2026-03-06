use axum::{Router, routing::get};

use crate::state::AppState;

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/me", get(handlers::me))
}
