use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn handle_404(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Redirect::to(&state.index_path)
}
