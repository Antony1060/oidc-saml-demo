use crate::models::{LoginSession, LoginSessionData};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect};
use reqwest::StatusCode;
use std::sync::Arc;

#[derive(Debug, serde::Deserialize)]
pub struct CallbackQuery {
    code: String,
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let authorized = state.oidc.authorize(&query.code).await;

    let authorized = match authorized {
        Ok(authorized) => authorized,
        Err(err) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
        }
    };

    if !state.oidc.validate_jwt(&authorized.access_token).await
        || !state.oidc.validate_jwt(&authorized.id_token).await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to validate access_token and id_token with provider JWKS",
        )
            .into_response();
    }

    let res =
        LoginSession::update_session(&session.session, &LoginSessionData::OIDC(authorized)).await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to("/").into_response()
}
