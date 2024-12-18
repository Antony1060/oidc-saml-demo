use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::SamlState;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn saml_login(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let authentication_request = state.saml.make_authentication_request().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create SAML authentication request: {}", err),
        )
    });

    let authentication_request = match authentication_request {
        Err(err) => return err.into_response(),
        Ok(val) => val,
    };

    let res = LoginSession::update_session(
        &session.session,
        &LoginSessionData::SAML(SamlState::Pending {
            request_id: authentication_request.id,
        }),
    )
    .await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(authentication_request.url.as_ref()).into_response()
}
