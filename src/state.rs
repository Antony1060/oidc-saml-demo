use crate::env::Environment;
use crate::sso::oidc::OidcProvider;

pub struct AppState {
    pub environment: Environment,
    pub oidc: OidcProvider,
}
