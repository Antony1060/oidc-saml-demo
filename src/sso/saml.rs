use crate::env::SamlConfig;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use samael::metadata::{EntityDescriptor, HTTP_REDIRECT_BINDING};
use samael::schema::AuthnRequest;
use samael::service_provider::ServiceProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlAuthorization {
    pub attributes: HashMap<String, String>,
    // TODO: improve with logout request
    pub logout_url: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SamlState {
    Pending { request_id: String },
    LoggedIn(SamlAuthorization),
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum SamlSetupError {
    #[error("Failed to fetch SAML provider descriptor: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to parse SAML provider descriptor: {0}")]
    SerializationError(#[from] samael::metadata::de::DeError),

    #[error("Failed to build SAML service provider: {0}")]
    ServiceProviderError(#[from] samael::service_provider::ServiceProviderBuilderError),
}

pub struct SamlServiceProvider {
    sp: ServiceProvider,
}

#[derive(Error, Debug)]
pub enum SamlError {
    #[error("Failed to decode base64: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Failed to parse UTF-8: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("Failed to parse XML: {0}")]
    XmlParseError(#[from] serde_xml_rs::Error),

    #[error("Failed to validate SAML response: {0}")]
    SamlValidationFailed(#[from] samael::service_provider::Error),

    #[error("{0}")]
    CustomError(String),
}

#[derive(Debug)]
pub struct SamlAuthenticationRequest {
    pub raw: AuthnRequest,
    pub id: String,
    pub url: Url,
}

impl SamlServiceProvider {
    pub async fn new(config: &SamlConfig) -> Result<Self, SamlSetupError> {
        debug!(
            "Loading SAML provider descriptor at {}",
            config.idp_metadata_url
        );
        let ipd_metadata: EntityDescriptor = samael::metadata::de::from_str(
            &reqwest::get(&config.idp_metadata_url).await?.text().await?,
        )
        .map(|metadata| {
            if !config.verify_signatures {
                Self::remove_signing_descriptors(metadata)
            } else {
                metadata
            }
        })?;

        let sp = samael::service_provider::ServiceProviderBuilder::default()
            .entity_id(config.entity_id.clone())
            .allow_idp_initiated(false)
            .idp_metadata(ipd_metadata)
            .acs_url(config.acs_url.full_url.clone())
            .slo_url(config.slo_url.full_url.clone())
            .build()?;

        Ok(Self { sp })
    }

    fn remove_signing_descriptors(mut metadata: EntityDescriptor) -> EntityDescriptor {
        metadata.idp_sso_descriptors = metadata.idp_sso_descriptors.map(|descriptors| {
            descriptors
                .into_iter()
                .map(|mut descriptor| {
                    descriptor.key_descriptors.retain(|key_descriptor| {
                        key_descriptor
                            .key_use
                            .as_ref()
                            .map(|key_use| key_use != "signing")
                            .unwrap_or(true)
                    });
                    descriptor
                })
                .collect()
        });

        metadata
    }

    pub fn make_authentication_request(&self) -> Result<SamlAuthenticationRequest, SamlError> {
        let authn_request = self.sp.make_authentication_request(
            &self
                .sp
                .sso_binding_location(HTTP_REDIRECT_BINDING)
                .ok_or_else(|| {
                    SamlError::CustomError("Failed to find SSO redirect binding".to_string())
                })?,
        )?;

        let url = authn_request.redirect("")?.unwrap();

        Ok(SamlAuthenticationRequest {
            id: authn_request.id.clone(),
            url,
            raw: authn_request,
        })
    }

    pub fn process_authentication_response(
        &self,
        raw_base64: &str,
        in_response_to: &str,
    ) -> Result<SamlAuthorization, SamlError> {
        let bytes = BASE64_STANDARD.decode(raw_base64)?;
        let decoded = std::str::from_utf8(&bytes)?;

        // validates signatures etc.
        self.sp
            .parse_xml_response(decoded, Some(&[in_response_to]))?;

        let response_parsed = serde_xml_rs::from_str(decoded)?;

        dbg!(response_parsed);

        Ok(SamlAuthorization {
            attributes: HashMap::from([
                ("name".to_string(), "Antonio Fran Trstenjak".to_string()),
                ("email".to_string(), "antony@local.antony.cloud".to_string()),
            ]),
            logout_url: "/saml/slo".to_string(),
        })
    }
}
