use std::{env, error::Error, net::SocketAddr};

mod error;
mod http;
mod infra;
mod modules;
mod state;

use crate::infra::telemetry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    dotenvy::dotenv().ok();
    telemetry::logging::init();

    let app_state = state::AppState::from_env()
        .await
        .expect("failed to init AppState");
    let app = http::build_router(app_state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:20443".to_string())
        .parse()?;

    println!("listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => {
            eprintln!("🛑 shutdown signal received (Ctrl+C)");
        }
        Err(err) => {
            eprintln!("🛑 failed to install Ctrl+C handler: {err}");
        }
    }
}
