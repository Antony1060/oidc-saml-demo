use crate::models::{LoginMethod, LoginSession, LoginSessionData};
use crate::state::AppState;
use crate::templates::{LoggedInTemplate, LoginTemplate};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    session: LoginSession,
) -> impl IntoResponse {
    match session.data {
        LoginSessionData::None => LoginTemplate.into_response(),
        LoginSessionData::OIDC(oidc) => {
            let userinfo = state.oidc.userinfo(&oidc).await;

            let userinfo = match userinfo {
                Ok(userinfo) => userinfo,
                Err(err) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
                }
            };

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
                .collect::<HashMap<String, String>>();

            let a = LoggedInTemplate {
                username: userinfo.get("name").map_or("unknown", |v| v).to_string(),
                login_method: LoginMethod::OIDC,
                scope_values: userinfo
                    .iter()
                    .filter(|(k, _)| *k != "sub")
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            };

            a.into_response()
        }
    }
}
