use std::sync::Arc;

use axum::Router;
use model::{AppState, Config};
mod service;
use sqlx::PgPool;
mod handlers;
mod model;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                // axum logs rejections from built-in extractors with the `axum::rejection`
                // target, at `TRACE` level. `axum::rejection=trace` enables showing those events
                format!(
                    "{}=debug,tower_http=debug,axum::rejection=trace,sqlx=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_string = std::env::var("DATABASE_URL").expect("DATABASE_URL MUST BE SET");

    let pool = PgPool::connect(&db_string)
        .await
        .expect("DB Connection failed");

    let app_state = AppState {
        pool,
        config: Arc::new(Config {
            jwt_secret: std::env::var("JWT_KEY").expect("JWT_KEY MUST BE SET"),
        }),
    };

    let app = Router::new()
        .nest("/api", handlers::get_router(app_state))
        .layer(TraceLayer::new_for_http());

    let listen_addr = format!(
        "0.0.0.0:{}",
        std::env::var("PORT").unwrap_or("3000".to_string())
    );
    tracing::info!("Listening on {listen_addr}");

    let listener = tokio::net::TcpListener::bind(listen_addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
