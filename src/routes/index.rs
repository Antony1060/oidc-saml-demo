use crate::models::{LoginMethod, LoginSession, LoginSessionData, UserAttribute};
use crate::sso::oidc::{OidcAuthentication, OidcProvider};
use crate::sso::saml::SamlState;
use crate::state::AppState;
use crate::templates::{LoggedInTemplate, LoginTemplate};
use axum::extract::State;
use axum::response::{IntoResponse, Redirect};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

struct ProviderData {
    login_method: LoginMethod,
    userinfo: HashMap<String, UserAttribute>,
    logout_url: String,
}

pub async fn handle_index(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let provider_data = match session.data {
        LoginSessionData::OIDC(oidc) => match get_oidc_data(&state.oidc, &oidc).await {
            Ok(userinfo) => userinfo,
            Err(_) => {
                // if we can't get userinfo, redirect to our logout handler
                //  we assume that at this point the session ended on the provider side
                //  so we can just clear our session
                return Redirect::to(&state.environment.oidc_config.logout_redirect_uri.path)
                    .into_response();
            }
        },
        LoginSessionData::SAML(SamlState::LoggedIn(saml)) => ProviderData {
            login_method: LoginMethod::SAML,
            userinfo: saml.attributes,
            logout_url: state.environment.saml_config.slo_url.path.to_string(),
        },
        _ => {
            return LoginTemplate {
                oidc_login_url: state.environment.oidc_config.redirect_uri.path.to_string(),
                saml_login_url: state.environment.saml_config.acs_url.path.to_string(),
            }
            .into_response()
        }
    };

    let userinfo = provider_data.userinfo;

    let username = 'username: {
        if let Some(UserAttribute {
            value: username, ..
        }) = userinfo.get("cn")
        {
            break 'username username.to_string();
        }

        if let Some(UserAttribute {
            value: username, ..
        }) = userinfo.get("name")
        {
            break 'username username.to_string();
        }

        "unknown".to_string()
    };

    LoggedInTemplate {
        username,
        login_method: provider_data.login_method,
        scope_values: {
            let mut vec = userinfo
                .into_iter()
                .filter(|(k, _)| *k != "sub")
                .collect::<Vec<_>>();

            vec.sort_by_key(|(key, _)| key.to_string());

            vec
        },
        logout_url: provider_data.logout_url,
    }
    .into_response()
}

async fn get_oidc_data(
    oidc: &OidcProvider,
    oidc_authentication: &OidcAuthentication,
) -> Result<ProviderData, reqwest::Error> {
    let userinfo = oidc.userinfo(oidc_authentication).await?;

    let userinfo = userinfo
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                match value {
                    Value::String(value) => UserAttribute {
                        attribute_type: "String".to_string(),
                        value,
                    },
                    // if result is an array of exactly one string value, treat it as a string in the UI
                    Value::Array(values)
                        if values.len() == 1 && matches!(&values[0], Value::String(_)) =>
                    {
                        UserAttribute {
                            attribute_type: "String".to_string(),
                            value: values[0].as_str().unwrap().to_string(),
                        }
                    }
                    _ => UserAttribute {
                        attribute_type: "JSON".to_string(),
                        value: value.to_string(),
                    },
                },
            )
        })
        .filter(|(key, _)| key != "sub")
        .collect::<HashMap<String, UserAttribute>>();

    Ok(ProviderData {
        login_method: LoginMethod::OIDC,
        userinfo,
        logout_url: oidc.logout_url(&oidc_authentication.id_token),
    })
}
