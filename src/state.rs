use crate::env::Environment;
use crate::sso::oidc::OidcProvider;
use samael::service_provider::ServiceProvider;

pub struct AppState {
    pub index_path: String,
    pub environment: Environment,
    pub oidc: OidcProvider,
    pub saml_sp: ServiceProvider,
}
