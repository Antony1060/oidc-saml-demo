use crate::models::{LoginSession, LoginSessionData};
use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn saml_slo(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    if let LoginSessionData::None = session.data {
        return Redirect::to(&state.index_path).into_response();
    }

    let res = LoginSession::update_session(&session.session, &LoginSessionData::None).await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(&state.index_path).into_response()
}
