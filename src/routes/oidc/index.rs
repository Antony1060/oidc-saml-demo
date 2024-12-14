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

pub async fn handle_index(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    let userinfo = match session.data {
        LoginSessionData::None => return LoginTemplate.into_response(),
        LoginSessionData::OIDC(oidc) => match get_userinfo_oidc(&state.oidc, &oidc).await {
            Ok(userinfo) => userinfo,
            Err(err) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }
        },
    };

    LoggedInTemplate {
        username: userinfo.get("name").map_or("unknown", |v| v).to_string(),
        login_method: LoginMethod::OIDC,
        scope_values: userinfo
            .iter()
            .filter(|(k, _)| *k != "sub")
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    }
    .into_response()
}

async fn get_userinfo_oidc(
    oidc: &OidcProvider,
    oidc_authorization: &OidcAuthorization,
) -> Result<HashMap<String, String>, reqwest::Error> {
    let userinfo = oidc.userinfo(oidc_authorization).await?;

    let userinfo = userinfo
        .into_iter()
        .map(|(key, value)| {
            (
                key,
                match value {
                    Value::String(value) => value,
                    _ => value.to_string(),
                },
            )
        })
        .filter(|(key, _)| key != "sub")
        .collect::<HashMap<String, String>>();

    Ok(userinfo)
}
