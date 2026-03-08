use crate::state::AppState;
use axum::Router;

use super::{admin, auth, system, users};

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(system::router())
        .merge(auth::router())
        .merge(users::router())
        .merge(admin::router())
}
