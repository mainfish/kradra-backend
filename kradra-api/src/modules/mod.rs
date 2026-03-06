use axum::Router;

use crate::state::AppState;

pub mod admin;
pub mod auth;
pub mod system;
pub mod users;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(system::router())
        .merge(auth::router())
        .merge(users::router())
        .merge(admin::router())
}
