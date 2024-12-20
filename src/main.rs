use crate::env::init_env;
use crate::state::AppState;
use crate::tracing::setup_tracing;
use axum::routing::{get, post};
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
    let session_layer = SessionManagerLayer::new(MemoryStore::default())
        // SAML will return the assertion to this path and the cookie won't be passed along
        //  if this is Lax or Strict
        // there might be a better way of handling this, but I guess it's fine for now,
        //  any help would be greatly appreciated
        .with_same_site(SameSite::None)
        .with_secure(true);

    let oidc_config = &env.oidc_config;
    let saml_config = &env.saml_config;

    let sensitive_paths: [&str; 4] = [
        &oidc_config.redirect_uri.path.to_ascii_lowercase(),
        &oidc_config.logout_redirect_uri.path.to_ascii_lowercase(),
        &saml_config.acs_url.path.to_ascii_lowercase(),
        &saml_config.slo_url.path.to_ascii_lowercase(),
    ];

    // setup index route, redirect URIs could use the same route
    //  callback and logout handler will redirect to correct index
    let index_route = ["/", "/home", "/main", "/index", "/root"]
        .into_iter()
        .find(|path| !sensitive_paths.contains(path))
        .expect("index route should be present");

    // setup state
    let state = Arc::new(AppState {
        oidc: sso::oidc::OidcProvider::new(&env.oidc_config).await?,
        saml: sso::saml::SamlServiceProvider::new(&env.saml_config).await?,
        environment: env,
        index_path: index_route.to_string(),
    });

    let oidc_config = &state.environment.oidc_config;
    let saml_config = &state.environment.saml_config;

    // setup router
    let app = Router::new()
        .route(index_route, get(routes::index::handle_index))
        // OIDC callback and logout paths are applied from the environment
        .route(
            &oidc_config.redirect_uri.path,
            get(routes::oidc::callback::oidc_callback),
        )
        .route(
            &oidc_config.logout_redirect_uri.path,
            get(routes::oidc::logout::oidc_logout),
        )
        // same with SAML
        .route(
            &saml_config.acs_url.path,
            get(routes::saml::acs::saml_acs_get),
        )
        .route(&saml_config.acs_url.path, post(routes::saml::acs::saml_acs))
        .route(
            &saml_config.slo_url.path,
            get(routes::saml::slo::saml_slo_get),
        )
        .route(&saml_config.slo_url.path, post(routes::saml::slo::saml_slo))
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
    info!("SAML ACS listening on: {}", saml_config.acs_url.path);
    info!("SAML SLO listening on URI: {}", saml_config.slo_url.path);

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
