use axum::{Router, routing::get};

use crate::state::AppState;

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/admin/ping", get(handlers::ping))
        .route("/api/admin/users", get(handlers::list_users))
        .route("/api/admin/users/{id}", get(handlers::get_user))
}
