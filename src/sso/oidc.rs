use serde::Deserialize;
use thiserror::Error;
use tracing::field::debug;
use crate::env::OidcConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct OidcProviderConfiguration {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    end_session_endpoint: String,
    jwks_uri: String,
    grant_types_supported: Vec<String>,
    response_types_supported: Vec<String>,
    scopes_supported: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct OidcProvider {
    provider_config: OidcProviderConfiguration,
    config: OidcConfig,
    http_client: reqwest::Client
}

#[derive(Debug, Error)]
pub enum OidcSetupError {
    #[error("Failed to fetch OIDC provider configuration: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("OIDC provider configuration validation failed: {0}")]
    ValidationError(String)
}

impl OidcProviderConfiguration {
    async fn from_url(url: &str) -> Result<OidcProviderConfiguration, OidcSetupError> {
        tracing::debug!("Loading OIDC provider configuration at {}", url);
        Ok(reqwest::get(url).await?.json().await?)
    }

    fn validate(self, config: &OidcConfig) -> Result<OidcProviderConfiguration, OidcSetupError> {
        if !self.grant_types_supported.contains(&"authorization_code".to_string()) {
            return Err(OidcSetupError::ValidationError("authorization_code grant type not supported".to_string()));
        }

        if !self.response_types_supported.contains(&"code".to_string()) {
            return Err(OidcSetupError::ValidationError("code response type not supported".to_string()));
        }

        if config.scopes.iter().any(|it| !self.scopes_supported.contains(it)) {
            return Err(OidcSetupError::ValidationError("some requested scopes are not supported".to_string()));
        }

        Ok(self)
    }
}

impl OidcProvider {

    pub async fn new(config: &OidcConfig)-> Result<OidcProvider, OidcSetupError> {
        let provider_config = OidcProviderConfiguration::from_url(&config.configuration_url).await?.validate(&config)?;

        let client = reqwest::Client::new();

        Ok(OidcProvider {
            provider_config,
            config: config.clone(),
            http_client: client
        })
    }

    pub async fn authorization_url(&self) -> String {
        format!("{}?client_id={}&response_type=code&redirect_uri={}&scope={}",
            self.provider_config.authorization_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&self.config.scopes.join(" "))
        )
    }

    pub async fn logout_url(&self, id_token: String) -> String {
        format!("{}?id_token_hind={}client_id={}&redirect_uri={}",
            self.provider_config.end_session_endpoint,
            urlencoding::encode(&id_token),
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.logout_redirect_uri)
        )
    }
}