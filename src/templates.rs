use crate::models::LoginMethod;
use askama::Template;
use serde::Serialize;

#[derive(Template, Serialize)]
#[template(path = "login.html")]
pub struct LoginTemplate;

#[derive(Template, Serialize)]
#[template(path = "logged-in.html")]
pub struct LoggedInTemplate {
    pub username: String,
    pub login_method: LoginMethod,
    pub scope_values: Vec<(String, (String, String))>,
    pub logout_url: String,
}
