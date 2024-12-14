use crate::models::{LoginSession, LoginSessionData};
use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let res = LoginSession::update_session(&session.session, &LoginSessionData::None).await;

    if let Err(err) = res {
        return err.into_response();
    }

    match session.data {
        LoginSessionData::None => Redirect::to("/").into_response(),
        LoginSessionData::OIDC(oidc) => {
            Redirect::to(&state.oidc.logout_url(&oidc.id_token)).into_response()
        }
    }
}
