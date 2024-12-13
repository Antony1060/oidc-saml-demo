use axum::response::{IntoResponse, Redirect};

pub async fn handle() -> impl IntoResponse {
    Redirect::to("/")
}
