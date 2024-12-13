use std::sync::Arc;
use ::tracing::info;
use crate::env::{init_env, Environment};
use crate::state::AppState;
use crate::tracing::setup_tracing;

mod env;
mod tracing;
mod state;
mod routes;
mod templates;
mod models;
mod sso;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_tracing();

    let env = init_env()?;

    let state = Arc::new(AppState {
        oidc: sso::oidc::OidcProvider::new(&env.oidc_config).await?,
        environment: env
    });

    info!("Using OIDC scopes: {}", state.environment.oidc_config.scopes.join(" "));

    info!("Server started on {}", state.environment.port);

    Ok(())
}
