use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::{SamlResponse, SamlState};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use std::sync::Arc;

pub async fn saml_slo_get(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let LoginSessionData::SAML(SamlState::LoggedIn(auth)) = session.data else {
        return Redirect::to(&state.index_path).into_response();
    };

    let logout_url = state.saml.make_logout_request(&auth).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create SAML logout request: {}", err),
        )
    });

    let (request_id, logout_url) = match logout_url {
        Err(err) => return err.into_response(),
        Ok(val) => val,
    };

    println!("respondez vous {}", request_id);

    let res = LoginSession::update_session(
        &session.session,
        &LoginSessionData::SAML(SamlState::LogoutPending { request_id }),
    )
    .await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(logout_url.as_str()).into_response()
}

pub async fn saml_slo(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
    Form(SamlResponse { SAMLResponse }): Form<SamlResponse>,
) -> impl IntoResponse {
    let LoginSessionData::SAML(SamlState::LogoutPending { request_id }) = session.data else {
        return Redirect::to(&state.index_path).into_response();
    };

    let Some(saml_response) = SAMLResponse else {
        return Redirect::to(&state.index_path).into_response();
    };

    let logout_response = state
        .saml
        .process_logout_response(&saml_response, &request_id)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse SAML response: {}", err),
            )
        });

    if let Err(err) = logout_response {
        return err.into_response();
    }

    let res = LoginSession::update_session(&session.session, &LoginSessionData::None).await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(&state.index_path).into_response()
}
