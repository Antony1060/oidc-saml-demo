use std::collections::HashMap;
use askama::Template;
use crate::models::LoginMethod;

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate;

#[derive(Template)]
#[template(path = "logged-in.html")]
pub struct LoggedInTemplate {
    username: String,
    login_method: LoginMethod,
    scope_values: Vec<(String, String)>
}