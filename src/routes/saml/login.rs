use crate::models::{LoginSession, LoginSessionData};
use crate::sso::saml::SamlState;
use crate::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use samael::metadata::HTTP_REDIRECT_BINDING;
use std::sync::Arc;

pub async fn saml_login(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let saml_sp = &state.saml_sp;

    let auth_request = saml_sp
        .make_authentication_request(&saml_sp.sso_binding_location(HTTP_REDIRECT_BINDING).unwrap())
        .unwrap();

    let redir = auth_request.redirect("").unwrap().unwrap();

    let res = LoginSession::update_session(
        &session.session,
        &LoginSessionData::SAML(SamlState::Pending {
            request_id: auth_request.id.clone(),
        }),
    )
    .await;

    if let Err(err) = res {
        return err.into_response();
    }

    Redirect::to(redir.as_ref()).into_response()
}
