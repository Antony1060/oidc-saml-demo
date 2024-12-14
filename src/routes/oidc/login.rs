use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn oidc_login(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Redirect::to(&state.oidc.authorization_url())
}
