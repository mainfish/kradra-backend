use axum::Router;

use crate::{error::AppError, modules, state::AppState};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(modules::router())
        .with_state(state)
        .fallback(fallback_404)
}

async fn fallback_404() -> AppError {
    AppError::NotFound
}
