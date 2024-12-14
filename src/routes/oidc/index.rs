use crate::templates::LoginTemplate;
use axum::response::IntoResponse;

pub async fn handle() -> impl IntoResponse {
    LoginTemplate
}
