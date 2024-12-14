use crate::env::OidcConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

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
    http_client: reqwest::Client,
}

#[derive(Debug, Error)]
pub enum OidcSetupError {
    #[error("Failed to fetch OIDC provider configuration: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("OIDC provider configuration validation failed: {0}")]
    ValidationError(String),
}

impl OidcProviderConfiguration {
    async fn from_url(url: &str) -> Result<OidcProviderConfiguration, OidcSetupError> {
        tracing::debug!("Loading OIDC provider configuration at {}", url);
        Ok(reqwest::get(url).await?.json().await?)
    }

    fn validate(self, config: &OidcConfig) -> Result<OidcProviderConfiguration, OidcSetupError> {
        if !self
            .grant_types_supported
            .contains(&"authorization_code".to_string())
        {
            return Err(OidcSetupError::ValidationError(
                "authorization_code grant type not supported".to_string(),
            ));
        }

        if !self.response_types_supported.contains(&"code".to_string()) {
            return Err(OidcSetupError::ValidationError(
                "code response type not supported".to_string(),
            ));
        }

        if config
            .scopes
            .iter()
            .any(|it| !self.scopes_supported.contains(it))
        {
            return Err(OidcSetupError::ValidationError(
                "some requested scopes are not supported".to_string(),
            ));
        }

        Ok(self)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcAuthorization {
    pub id_token: String,
    pub access_token: String,
    pub token_type: String,
}

impl OidcProvider {
    pub async fn new(config: &OidcConfig) -> Result<OidcProvider, OidcSetupError> {
        let provider_config = OidcProviderConfiguration::from_url(&config.configuration_url)
            .await?
            .validate(config)?;

        let client = reqwest::Client::new();

        Ok(OidcProvider {
            provider_config,
            config: config.clone(),
            http_client: client,
        })
    }

    pub fn authorization_url(&self) -> String {
        format!(
            "{}?client_id={}&response_type=code&redirect_uri={}&scope={}",
            self.provider_config.authorization_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&self.config.scopes.join(" "))
        )
    }

    pub fn logout_url(&self, id_token: &str) -> String {
        format!(
            "{}?id_token_hint={}&client_id={}&post_logout_redirect_uri={}",
            self.provider_config.end_session_endpoint,
            urlencoding::encode(id_token),
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.logout_redirect_uri)
        )
    }

    pub async fn authorize(&self, code: &str) -> Result<OidcAuthorization, reqwest::Error> {
        let data = self
            .http_client
            .post(&self.provider_config.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
            ])
            .send()
            .await?
            .json::<OidcAuthorization>()
            .await?;

        dbg!(&data);

        Ok(data)
    }

    pub async fn userinfo(
        &self,
        authorization: &OidcAuthorization,
    ) -> Result<HashMap<String, serde_json::Value>, reqwest::Error> {
        let data = self
            .http_client
            .get(&self.provider_config.userinfo_endpoint)
            .header(
                reqwest::header::AUTHORIZATION,
                format!(
                    "{} {}",
                    authorization.token_type, authorization.access_token
                ),
            )
            .send()
            .await?
            .json::<HashMap<String, serde_json::Value>>()
            .await?;

        dbg!(&data);

        Ok(data)
    }
}
