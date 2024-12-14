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

#[derive(Debug)]
pub struct Environment {
    pub port: u16,
    pub oidc_config: OidcConfig,
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

            let mut scopes: Vec<String> = scopes.split(' ').map(|s| s.to_string()).collect();

            for scope in DEFAULT_SCOPES {
                if !scope.contains(scope) {
                    scopes.push(scope.to_string())
                }
            }

            scopes
        },
    })
}

pub fn init_env() -> Result<Environment, EnvError> {
    dotenv::dotenv().ok();

    Ok(Environment {
        port: get_env("PORT")?.parse()?,
        oidc_config: init_oidc_config()?,
    })
}
