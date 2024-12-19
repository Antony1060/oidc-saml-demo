use crate::models::{LoginMethod, UserAttribute};
use askama::Template;
use serde::Serialize;

#[derive(Template, Serialize)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub oidc_login_url: String,
    pub saml_login_url: String,
}

#[derive(Template, Serialize)]
#[template(path = "logged-in.html")]
pub struct LoggedInTemplate {
    pub username: String,
    pub login_method: LoginMethod,
    pub scope_values: Vec<(String, UserAttribute)>,
    pub logout_url: String,
}
