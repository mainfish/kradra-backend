use axum::{
    Router,
    routing::{get, patch},
};

use crate::state::AppState;

use super::handlers;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/admin/ping", get(handlers::ping))
        .route("/api/admin/users", get(handlers::list_users))
        .route("/api/admin/users/{id}", get(handlers::get_user))
        .route(
            "/api/admin/users/{id}/role",
            patch(handlers::update_user_role),
        )
        .route(
            "/api/admin/users/{id}/active",
            patch(handlers::update_user_active),
        )
}
