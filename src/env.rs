use crate::sso::saml::SamlPrivateKeyType;
use thiserror::Error;
use tracing::warn;
use url::Url;

const DEFAULT_SCOPES: [&str; 1] = ["openid"];

#[derive(Debug, Clone)]
pub struct BaseUrlParts {
    pub full_url: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub configuration_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: BaseUrlParts,
    pub logout_redirect_uri: BaseUrlParts,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SamlConfig {
    pub idp_metadata_url: String,
    pub entity_id: String,
    pub acs_url: BaseUrlParts,
    pub slo_url: BaseUrlParts,
    pub verify_signatures: bool,
    pub private_key: String,
    pub private_key_type: SamlPrivateKeyType,
}

#[derive(Debug)]
pub struct Environment {
    pub port: u16,
    pub oidc_config: OidcConfig,
    pub saml_config: SamlConfig,
}

#[derive(Debug, Error)]
pub enum EnvError {
    #[error("Invalid environment variable: {0}")]
    VarError(&'static str),

    #[error("Invalid environment variable: {0}")]
    ParseIntError(#[from] std::num::ParseIntError),
}

fn get_env(name: &'static str) -> Result<String, EnvError> {
    std::env::var(name).map_err(|_| EnvError::VarError(name))
}

fn parse_url_parts(var: &'static str, url: &str) -> Result<BaseUrlParts, EnvError> {
    let url = Url::parse(url).map_err(|err| {
        warn!("Failed to parse URL: {}", err);
        EnvError::VarError(var)
    })?;

    Ok(BaseUrlParts {
        full_url: url.to_string(),
        path: url.path().to_string(),
    })
}

fn init_oidc_config() -> Result<OidcConfig, EnvError> {
    Ok(OidcConfig {
        configuration_url: get_env("OIDC_CONFIGURATION_URL")?,
        client_id: get_env("OIDC_CLIENT_ID")?,
        client_secret: get_env("OIDC_CLIENT_SECRET")?,
        redirect_uri: get_env("OIDC_REDIRECT_URI")
            .and_then(|val| parse_url_parts("OIDC_REDIRECT_URI", &val))?,
        logout_redirect_uri: get_env("OIDC_LOGOUT_REDIRECT_URI")
            .and_then(|val| parse_url_parts("OIDC_LOGOUT_REDIRECT_URI", &val))?,
        scopes: 'oidc: {
            let raw = get_env("OIDC_SCOPES");

            let Ok(scopes) = raw else {
                warn!(
                    "env: OIDC_SCOPES not defined, defaulting to: {}",
                    DEFAULT_SCOPES.join(" ")
                );
                break 'oidc DEFAULT_SCOPES.iter().map(|&it| it.to_string()).collect();
            };

            let mut scopes: Vec<String> = scopes.split(',').map(|s| s.to_string()).collect();

            for scope in DEFAULT_SCOPES {
                if !scope.contains(scope) {
                    scopes.push(scope.to_string())
                }
            }

            scopes
        },
    })
}

fn init_saml_config() -> Result<SamlConfig, EnvError> {
    Ok(SamlConfig {
        idp_metadata_url: get_env("SAML_IDP_METADATA_URL")?,
        entity_id: get_env("SAML_SP_ENTITY_ID")?,
        acs_url: get_env("SAML_SP_ACS_URL")
            .and_then(|val| parse_url_parts("SAML_SP_ACS_URL", &val))?,
        slo_url: get_env("SAML_SP_SLO_URL")
            .and_then(|val| parse_url_parts("SAML_SP_SLO_URL", &val))?,
        verify_signatures: get_env("SAML_SP_VERIFY_SIGNATURES")?
            .parse()
            .map_err(|_| EnvError::VarError("SAML_SP_VERIFY_SIGNATURES"))?,
        private_key: get_env("SAML_SP_PRIVATE_KEY_LOCATION")?,
        private_key_type: get_env("SAML_SP_PRIVATE_KEY_TYPE").map(|val| {
            match val.to_ascii_lowercase().as_str() {
                "rsa" => Ok(SamlPrivateKeyType::Rsa),
                "ecdsa" => Ok(SamlPrivateKeyType::Ecdsa),
                _ => Err(EnvError::VarError("SAML_SP_PRIVATE_KEY_TYPE")),
            }
        })??,
    })
}

pub fn init_env() -> Result<Environment, EnvError> {
    dotenv::dotenv().ok();

    Ok(Environment {
        port: get_env("PORT")?.parse()?,
        oidc_config: init_oidc_config()?,
        saml_config: init_saml_config()?,
    })
}
