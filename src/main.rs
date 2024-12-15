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

    // setup sessions
    let session_layer =
        SessionManagerLayer::new(MemoryStore::default()).with_same_site(SameSite::Lax);

    // setup index route, redirect URIs could use the same route
    //  callback and logout handler will redirect to correct index
    let index_route = ["/", "/home", "/main"]
        .into_iter()
        .find(|path| {
            let oidc_config = &env.oidc_config;

            let redirect_uris: [&str; 2] = [
                &oidc_config.redirect_uri.path.to_ascii_lowercase(),
                &oidc_config.logout_redirect_uri.path.to_ascii_lowercase(),
            ];

            !redirect_uris.contains(path)
        })
        .expect("index route should be present");

    // setup state
    let state = Arc::new(AppState {
        oidc: sso::oidc::OidcProvider::new(&env.oidc_config).await?,
        environment: env,
        index_path: index_route.to_string(),
    });

    let oidc_config = &state.environment.oidc_config;

    // setup router
    let app = Router::new()
        .route(index_route, get(routes::index::handle_index))
        // OIDC callback and logout paths are applied from the environment
        .route(
            &oidc_config.redirect_uri.path,
            get(routes::oidc::callback::handle_callback),
        )
        .route(
            &oidc_config.logout_redirect_uri.path,
            get(routes::oidc::logout::oidc_logout),
        )
        .route("/oidc/login", get(routes::oidc::login::oidc_login))
        .fallback(routes::four_oh_four::handle_404)
        .layer(session_layer)
        .with_state(state.clone());

    let listener =
        tokio::net::TcpListener::bind(format!("0.0.0.0:{}", &state.environment.port)).await?;

    info!("Using OIDC scopes: {}", oidc_config.scopes.join(" "));

    info!("Index listening on: {}", index_route);
    info!(
        "OIDC callback listening on: {}",
        oidc_config.redirect_uri.path
    );
    info!(
        "OIDC logout callback listening on URI: {}",
        oidc_config.logout_redirect_uri.path
    );

    info!("Server started on {}", state.environment.port);

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = axum::serve::serve(listener, app) => {},
        _ = tokio::signal::ctrl_c() => {
            info!("Shutting down");
        },
        _ = sigterm.recv() => {
            info!("Shutting down");
        }
    }

    Ok(())
}
