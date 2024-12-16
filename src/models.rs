use crate::sso::oidc::OidcAuthorization;
use crate::sso::saml::SamlState;
use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use tower_sessions::Session;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize)]
pub enum LoginMethod {
    OIDC,
    SAML,
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LoginMethod::OIDC => "OpenID Connect",
                LoginMethod::SAML => "Security Assertion Markup Language",
            }
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Default, Serialize, Deserialize)]
pub enum LoginSessionData {
    #[default]
    None,
    OIDC(OidcAuthorization),
    SAML(SamlState),
}

pub struct LoginSession {
    pub session: Session,
    pub data: LoginSessionData,
}

impl LoginSession {
    const LOGIN_SESSION_KEY: &'static str = "login_session";

    pub async fn update_session(
        session: &Session,
        data: &LoginSessionData,
    ) -> Result<(), (StatusCode, &'static str)> {
        session
            .insert(Self::LOGIN_SESSION_KEY, data)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "session error"))?;

        Ok(())
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for LoginSession
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(req: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(req, state).await?;

        let data: LoginSessionData = session
            .get(Self::LOGIN_SESSION_KEY)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "session error"))?
            .unwrap_or_default();

        Self::update_session(&session, &data).await?;

        Ok(LoginSession { session, data })
    }
}
