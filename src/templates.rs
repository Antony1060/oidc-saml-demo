use crate::models::LoginMethod;
use askama::Template;
use serde::Serialize;

#[derive(Template, Serialize)]
#[template(path = "login.html")]
pub struct LoginTemplate;

#[derive(Template, Serialize)]
#[template(path = "logged-in.html")]
pub struct LoggedInTemplate {
    username: String,
    login_method: LoginMethod,
    scope_values: Vec<(String, String)>,
}
