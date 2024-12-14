use crate::models::{LoginMethod, LoginSession, LoginSessionData};
use crate::sso::oidc::{OidcAuthorization, OidcProvider};
use crate::state::AppState;
use crate::templates::{LoggedInTemplate, LoginTemplate};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

struct ProviderData {
    userinfo: HashMap<String, String>,
    logout_url: String,
}

pub async fn handle_index(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let provider_data = match session.data {
        LoginSessionData::None => return LoginTemplate.into_response(),
        LoginSessionData::OIDC(oidc) => match get_oidc_data(&state.oidc, &oidc).await {
            Ok(userinfo) => userinfo,
            Err(err) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
        },
    };

    let userinfo = &provider_data.userinfo;

    let username = 'username: {
        if let Some(username) = userinfo.get("cn") {
            break 'username username.to_string();
        }

        if let Some(username) = userinfo.get("name") {
            break 'username username.to_string();
        }

        "unknown".to_string()
    };

    LoggedInTemplate {
        username,
        login_method: LoginMethod::OIDC,
        scope_values: userinfo
            .iter()
            .filter(|(k, _)| *k != "sub")
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        logout_url: provider_data.logout_url,
    }
    .into_response()
}

async fn get_oidc_data(
    oidc: &OidcProvider,
    oidc_authorization: &OidcAuthorization,
) -> Result<ProviderData, reqwest::Error> {
    let userinfo = oidc.userinfo(oidc_authorization).await?;

    let userinfo = userinfo
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                match value {
                    Value::String(value) => value,
                    // if result is an array of exactly one string value, treat it as a string in the UI
                    Value::Array(values)
                        if values.len() == 1 && matches!(&values[0], Value::String(_)) =>
                    {
                        values[0].as_str().unwrap().to_string()
                    }
                    _ => value.to_string(),
                },
            )
        })
        .filter(|(key, _)| key != "sub")
        .collect::<HashMap<String, String>>();

    Ok(ProviderData {
        userinfo,
        logout_url: oidc.logout_url(&oidc_authorization.id_token),
    })
}
