use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum SamlState {
    Pending { request_id: String },
    LoggedIn,
}
