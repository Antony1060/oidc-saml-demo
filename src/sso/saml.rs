use crate::env::SamlConfig;
use crate::models::UserAttribute;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use samael::attribute::Attribute;
use samael::metadata::{EntityDescriptor, HTTP_REDIRECT_BINDING};
use samael::schema::{Assertion, Subject, SubjectNameID};
use samael::service_provider::ServiceProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlAuthorization {
    pub attributes: HashMap<String, UserAttribute>,
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

    #[error("Failed to validate SAML response: {0}")]
    SamlValidationFailed(#[from] samael::service_provider::Error),

    #[error("Failed to process SAML response: {0}")]
    SamaelError(#[from] Box<dyn std::error::Error>),

    #[error("{0}")]
    CustomError(String),
}

#[derive(Debug)]
pub struct SamlAuthenticationRequest {
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
        })
    }

    pub fn process_authentication_response(
        &self,
        raw_base64: &str,
        in_response_to: &str,
    ) -> Result<SamlAuthorization, SamlError> {
        let bytes = BASE64_STANDARD.decode(raw_base64)?;
        let decoded = std::str::from_utf8(&bytes)?;

        let assertion = self
            .sp
            .parse_xml_response(decoded, Some(&[in_response_to]))?;

        let attributes = Self::parse_authentication_response_attributes(assertion)?;

        Ok(SamlAuthorization {
            attributes,
            logout_url: "/saml/slo".to_string(),
        })
    }

    fn parse_authentication_response_attributes(
        assertion: Assertion,
    ) -> Result<HashMap<String, UserAttribute>, SamlError> {
        let Some(Subject {
            name_id:
                Some(SubjectNameID {
                    value: subject_name,
                    ..
                }),
            ..
        }) = assertion.subject
        else {
            return Err(SamlError::CustomError(
                "Failed to parse assertion".to_string(),
            ));
        };

        let Some(attribute_statements) = assertion.attribute_statements else {
            return Err(SamlError::CustomError(
                "Failed to parse attributes".to_string(),
            ));
        };

        let mut attributes: HashMap<String, UserAttribute> = attribute_statements
            .into_iter()
            .flat_map(|attribute_statement| {
                attribute_statement
                    .attributes
                    .into_iter()
                    .filter_map(|attribute| {
                        dbg!(&attribute);
                        Self::parse_attribute(attribute)
                    })
            })
            .collect();

        dbg!(&attributes);

        attributes.insert(
            "name".to_string(),
            UserAttribute {
                attribute_type: "xs:string".to_string(),
                value: subject_name,
            },
        );

        Ok(attributes)
    }

    fn parse_attribute(attribute: Attribute) -> Option<(String, UserAttribute)> {
        Some((
            attribute.friendly_name.or(attribute.name)?,
            attribute
                .values
                .into_iter()
                .filter_map(|value| {
                    Some(UserAttribute {
                        value: value.value?,
                        attribute_type: value.attribute_type.unwrap_or("String".to_string()),
                    })
                })
                // potential loss of type info
                //  we hope that type is the same for attribute with same name
                .reduce(|mut acc, curr| {
                    acc.value.push_str(", ");
                    acc.value.push_str(&curr.value);

                    acc
                })?,
        ))
    }
}
