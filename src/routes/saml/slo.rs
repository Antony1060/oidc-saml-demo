use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::{SamlResponse, SamlState};
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use std::sync::Arc;

pub async fn saml_slo(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
    Query(SamlResponse { SAMLResponse }): Query<SamlResponse>,
) -> impl IntoResponse {
    if let LoginSessionData::None = session.data {
        return Redirect::to(&state.index_path).into_response();
    }

    if let LoginSessionData::SAML(SamlState::LoggedIn(auth)) = session.data {
        let logout_url = state
            .saml
            .make_logout_request(&auth.subject_name_id)
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create SAML logout request: {}", err),
                )
            });

        let (request_id, logout_url) = match logout_url {
            Err(err) => return err.into_response(),
            Ok(val) => val,
        };

        let res = LoginSession::update_session(
            &session.session,
            &LoginSessionData::SAML(SamlState::LogoutPending { request_id }),
        )
        .await;

        if let Err(err) = res {
            return err.into_response();
        }

        return Redirect::to(logout_url.as_str()).into_response();
    };

    let LoginSessionData::SAML(SamlState::LogoutPending { request_id }) = session.data else {
        return Redirect::to(&state.index_path).into_response();
    };

    let Some(saml_response) = SAMLResponse else {
        return Redirect::to(&state.index_path).into_response();
    };

    dbg!(&request_id);
    dbg!(&saml_response);

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
