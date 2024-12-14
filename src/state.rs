use crate::env::Environment;
use crate::sso::oidc::OidcProvider;

pub struct AppState {
    pub index_path: String,
    pub environment: Environment,
    pub oidc: OidcProvider,
}
