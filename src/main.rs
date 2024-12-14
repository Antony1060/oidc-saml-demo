use crate::env::init_env;
use crate::state::AppState;
use crate::tracing::setup_tracing;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tower_sessions::cookie::SameSite;
use tower_sessions::{MemoryStore, SessionManagerLayer};
use ::tracing::info;

mod env;
mod models;
mod routes;
mod sso;
mod state;
mod templates;
mod tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing();

    let env = init_env()?;

    let state = Arc::new(AppState {
        oidc: sso::oidc::OidcProvider::new(&env.oidc_config).await?,
        environment: env,
    });

    let session_layer =
        SessionManagerLayer::new(MemoryStore::default()).with_same_site(SameSite::Lax);

    let app = Router::new()
        .route("/", get(routes::oidc::index::handle))
        .nest(
            "/oidc",
            Router::new()
                .route("/login", get(routes::oidc::login::handle))
                .route("/callback", get(routes::oidc::callback::handle))
                .route("/logout", get(routes::oidc::logout::handle)),
        )
        .layer(session_layer)
        .with_state(state.clone());

    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &state.environment.port)).await?;

    info!(
        "Using OIDC scopes: {}",
        state.environment.oidc_config.scopes.join(" ")
    );

    info!("Server started on {}", state.environment.port);

    axum::serve::serve(listener, app).await?;

    Ok(())
}
