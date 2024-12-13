use crate::state::AppState;
use axum::extract::State;
use axum::response::Redirect;
use std::sync::Arc;

pub async fn handle(State(state): State<Arc<AppState>>) -> Redirect {
    Redirect::to(&state.oidc.authorization_url())
}
