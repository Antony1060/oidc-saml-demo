use crate::env::SamlConfig;
use crate::models::UserAttribute;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use multimap::MultiMap;
use openssl::pkey::PKey;
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

    #[error("Failed to read private key: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Failed to parse private key: {0}")]
    OpensslError(#[from] openssl::error::ErrorStack),
}

#[derive(Debug, Clone)]
pub enum SamlPrivateKeyType {
    Rsa,
    Ecdsa,
}

pub struct SamlServiceProvider {
    sp: ServiceProvider,
    private_key: PKey<openssl::pkey::Private>,
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

        let private_key_bytes = std::fs::read(&config.private_key)?;

        let private_key = match config.private_key_type {
            SamlPrivateKeyType::Rsa => {
                PKey::from_rsa(openssl::rsa::Rsa::private_key_from_pem(&private_key_bytes)?)?
            }
            // TODO: untested
            SamlPrivateKeyType::Ecdsa => PKey::from_ec_key(
                openssl::ec::EcKey::private_key_from_pem(&private_key_bytes)?,
            )?,
        };

        let sp = samael::service_provider::ServiceProviderBuilder::default()
            .entity_id(config.entity_id.clone())
            .allow_idp_initiated(false)
            .idp_metadata(ipd_metadata)
            .acs_url(config.acs_url.full_url.clone())
            .slo_url(config.slo_url.full_url.clone())
            .build()?;

        Ok(Self { sp, private_key })
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

        let url = authn_request
            .signed_redirect("", self.private_key.clone())?
            .unwrap();

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

        let mut attributes: MultiMap<String, UserAttribute> = attribute_statements
            .into_iter()
            .flat_map(|attribute_statement| {
                attribute_statement
                    .attributes
                    .into_iter()
                    .filter_map(Self::parse_attribute)
            })
            .collect();

        attributes.insert(
            "name".to_string(),
            UserAttribute {
                attribute_type: "xs:string".to_string(),
                value: subject_name,
            },
        );

        Ok(attributes
            .into_iter()
            .filter_map(|(key, value)| Some((key, Self::collapse_user_attributes(value)?)))
            .collect())
    }

    fn parse_attribute(attribute: Attribute) -> Option<(String, UserAttribute)> {
        let attributes_iter = attribute.values.into_iter().filter_map(|value| {
            Some(UserAttribute {
                value: value.value?,
                attribute_type: value.attribute_type.unwrap_or("String".to_string()),
            })
        });

        Some((
            attribute.friendly_name.or(attribute.name)?,
            Self::collapse_user_attributes(attributes_iter)?,
        ))
    }

    // potential loss of type info
    //  we hope that type is the same for attribute with same name
    // None if supplied list is empty
    fn collapse_user_attributes<T>(attributes: T) -> Option<UserAttribute>
    where
        T: IntoIterator<Item = UserAttribute>,
    {
        attributes.into_iter().reduce(|mut acc, curr| {
            acc.value.push_str(", ");
            acc.value.push_str(&curr.value);

            acc
        })
    }
}
