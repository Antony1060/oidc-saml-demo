use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::{SamlResponse, SamlState};
use crate::state::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Form;
use std::sync::Arc;

pub async fn saml_acs_get(
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

pub async fn saml_acs(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
    Form(SamlResponse { SAMLResponse }): Form<SamlResponse>,
) -> impl IntoResponse {
    let LoginSessionData::SAML(SamlState::Pending { request_id }) = session.data else {
        return Redirect::to(&state.index_path).into_response();
    };

    let Some(saml_response) = SAMLResponse else {
        return Redirect::to(&state.index_path).into_response();
    };

    let authorization = state
        .saml
        .process_authentication_response(&saml_response, &request_id)
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to parse SAML response: {}", err),
            )
        });

    match authorization {
        Ok(authorization) => {
            let res = LoginSession::update_session(
                &session.session,
                &LoginSessionData::SAML(SamlState::LoggedIn(authorization)),
            )
            .await;

            if let Err(err) = res {
                return err.into_response();
            }

            Redirect::to(&state.index_path).into_response()
        }
        Err(err) => {
            let res = LoginSession::update_session(&session.session, &LoginSessionData::None).await;

            if let Err(err) = res {
                return err.into_response();
            }

            err.into_response()
        }
    }
}
