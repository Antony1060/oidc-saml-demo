use crate::env::Environment;
use crate::sso::oidc::OidcProvider;

#[derive(Debug)]
pub struct AppState {
    pub environment: Environment,
    pub oidc: OidcProvider
}