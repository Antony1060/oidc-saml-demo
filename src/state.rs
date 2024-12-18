use crate::env::Environment;
use crate::sso::oidc::OidcProvider;
use crate::sso::saml::SamlServiceProvider;

pub struct AppState {
    pub index_path: String,
    pub environment: Environment,
    pub oidc: OidcProvider,
    pub saml: SamlServiceProvider,
}
