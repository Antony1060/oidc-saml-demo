use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::SamlState;
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use std::sync::Arc;

#[allow(non_snake_case)]
#[derive(Debug, serde::Deserialize)]
pub struct SamlResponse {
    SAMLResponse: String,
}

pub async fn saml_acs(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
    Form(SamlResponse { SAMLResponse }): Form<SamlResponse>,
) -> impl IntoResponse {
    let LoginSessionData::SAML(SamlState::Pending { request_id }) = session.data else {
        return Redirect::to(&state.index_path).into_response();
    };

    let res = state
        .saml_sp
        .parse_base64_response(&SAMLResponse, Some(&[&request_id]))
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse SAML response: {}", err),
            )
        });

    if let Err(err) = res {
        let res = LoginSession::update_session(&session.session, &LoginSessionData::None).await;

        if let Err(err) = res {
            return err.into_response();
        }

        return err.into_response();
    }

    let res = LoginSession::update_session(
        &session.session,
        &LoginSessionData::SAML(SamlState::LoggedIn),
    )
    .await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(&state.index_path).into_response()
}
