use axum::Router;
use axum::http::{HeaderValue, Method, header};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::{error::AppError, modules, state::AppState};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .merge(modules::router())
        .with_state(state)
        .fallback(fallback_404)
        .layer(cors_layer_from_env())
}

async fn fallback_404() -> AppError {
    AppError::NotFound
}

fn cors_layer_from_env() -> CorsLayer {
    let origins_raw = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
    let allow_credentials = std::env::var("CORS_ALLOW_CREDENTIALS")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let origins: Vec<HeaderValue> = origins_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();

    let mut layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([header::SET_COOKIE]);

    // If no origins configured, effectively disable CORS.
    layer = if origins.is_empty() {
        layer.allow_origin(AllowOrigin::exact(HeaderValue::from_static("null")))
    } else {
        layer.allow_origin(AllowOrigin::list(origins))
    };

    if allow_credentials {
        layer = layer.allow_credentials(true);
    }

    layer
}
