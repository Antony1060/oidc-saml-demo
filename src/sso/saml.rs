use crate::env::SamlConfig;
use crate::models::UserAttribute;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;
use flate2::{write::DeflateEncoder, Compression};
use multimap::MultiMap;
use openssl::pkey::PKey;
use samael::attribute::Attribute;
use samael::metadata::{EntityDescriptor, HTTP_REDIRECT_BINDING};
use samael::schema::{Assertion, Issuer, LogoutRequest, NameID, Subject, SubjectNameID};
use samael::service_provider::{Error as SamaelSPError, ServiceProvider};
use samael::traits::ToXml;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use thiserror::Error;
use tracing::{debug, warn};
use url::Url;

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlNameId {
    pub value: String,
    pub format: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, serde::Deserialize)]
pub struct SamlResponse {
    pub SAMLResponse: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SamlAuthorization {
    pub attributes: HashMap<String, UserAttribute>,
    pub subject_name_id: SamlNameId,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SamlState {
    Pending { request_id: String },
    LoggedIn(SamlAuthorization),
    LogoutPending { request_id: String },
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
        let mut authn_request = self.sp.make_authentication_request(
            &self
                .sp
                .sso_binding_location(HTTP_REDIRECT_BINDING)
                .ok_or_else(|| {
                    SamlError::CustomError("Failed to find SSO redirect binding".to_string())
                })?,
        )?;

        authn_request.id = Self::make_openssl_rand_id()?;

        let url = authn_request
            .signed_redirect("", self.private_key.clone())?
            .ok_or(SamlError::CustomError(
                "Failed to make signed authentication request".to_string(),
            ))?;

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
        let assertion = self
            .sp
            .parse_base64_response(raw_base64, Some(&[in_response_to]))?;

        let (name_id, attributes) = Self::parse_authentication_response_attributes(assertion)?;

        Ok(SamlAuthorization {
            attributes,
            subject_name_id: SamlNameId {
                value: name_id.value,
                format: name_id.format,
            },
        })
    }

    pub fn process_logout_response(
        &self,
        raw_base64: &str,
        in_response_to: &str,
    ) -> Result<(), SamlError> {
        let assertion = self
            .sp
            .parse_base64_response(raw_base64, Some(&[in_response_to]))?;

        dbg!(&assertion);

        Ok(())
    }

    pub fn make_logout_request(
        &self,
        target_name_id: &SamlNameId,
    ) -> Result<(String, Url), SamlError> {
        let request_id = Self::make_openssl_rand_id()?;

        // not natively supported in samael :/
        let logout_request = LogoutRequest {
            id: Some(Self::make_openssl_rand_id()?),
            version: Some("2.0".to_string()),
            issue_instant: Some(Utc::now()),
            destination: self.sp.slo_binding_location(HTTP_REDIRECT_BINDING),
            issuer: Some(Issuer {
                format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:entity".to_string()),
                value: self.sp.entity_id.clone(),
                ..Issuer::default()
            }),
            signature: None,
            name_id: Some(NameID {
                value: target_name_id.value.clone(),
                format: target_name_id.format.clone(),
            }),
            session_index: None,
        };

        let url = Self::signed_redirect(&logout_request, None, self.private_key.clone())?.ok_or(
            SamlError::CustomError("Failed to make signed logout request".to_string()),
        )?;

        Ok((request_id, url))
    }

    fn parse_authentication_response_attributes(
        assertion: Assertion,
    ) -> Result<(SubjectNameID, HashMap<String, UserAttribute>), SamlError> {
        let Some(Subject {
            name_id: Some(subject_name_id),
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
                value: subject_name_id.value.clone(),
            },
        );

        Ok((
            subject_name_id,
            attributes
                .into_iter()
                .filter_map(|(key, value)| Some((key, Self::collapse_user_attributes(value)?)))
                .collect(),
        ))
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

    fn make_openssl_rand_id() -> Result<String, SamlError> {
        let mut buffer = [0; 16];
        openssl::rand::rand_bytes(&mut buffer).map_err(|errs| {
            warn!("OpenSSL rand error: {errs:?}");
            SamlError::CustomError("Failed to generate openssl random id".to_string())
        })?;

        Ok(hex::encode(buffer))
    }

    // these 2 functions are copied (and slightly modified) from samael source for AuthnRequest
    //  used only for LogoutRequest, since it's not natively in samael
    // NOTE(antony): might be worth making a PR for this
    fn redirect(
        request: &LogoutRequest,
        relay_state: Option<&str>,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let mut compressed_buf = vec![];
        {
            let mut encoder = DeflateEncoder::new(&mut compressed_buf, Compression::default());
            encoder.write_all(request.to_string()?.as_bytes())?;
        }
        let encoded = BASE64_STANDARD.encode(&compressed_buf);

        if let Some(destination) = request.destination.as_ref() {
            let mut url: Url = destination.parse()?;
            url.query_pairs_mut().append_pair("SAMLRequest", &encoded);
            if let Some(relay_state) = relay_state {
                url.query_pairs_mut().append_pair("RelayState", relay_state);
            }
            Ok(Some(url))
        } else {
            Ok(None)
        }
    }

    fn signed_redirect(
        request: &LogoutRequest,
        relay_state: Option<&str>,
        private_key: PKey<openssl::pkey::Private>,
    ) -> Result<Option<Url>, Box<dyn std::error::Error>> {
        let unsigned_url = Self::redirect(request, relay_state)?;

        let Some(mut unsigned_url) = unsigned_url else {
            return Ok(unsigned_url);
        };

        if private_key.ec_key().is_ok() {
            unsigned_url.query_pairs_mut().append_pair(
                "SigAlg",
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            );
        } else if private_key.rsa().is_ok() {
            unsigned_url.query_pairs_mut().append_pair(
                "SigAlg",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            );
        } else {
            return Err(SamaelSPError::UnsupportedKey)?;
        }

        let string_to_sign: String = unsigned_url
            .query()
            .ok_or(SamaelSPError::UnexpectedError)?
            .to_string();

        let pkey = private_key;

        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), pkey.as_ref())?;

        signer.update(string_to_sign.as_bytes())?;

        unsigned_url
            .query_pairs_mut()
            .append_pair("Signature", &BASE64_STANDARD.encode(signer.sign_to_vec()?));

        // Past this point, it's a signed url :)
        Ok(Some(unsigned_url))
    }
}
