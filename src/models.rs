use std::fmt::{Display, Formatter};

pub enum LoginMethod {
    OIDC,
    SAML
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            LoginMethod::OIDC => "OpenID Connect (OIDC)",
            LoginMethod::SAML => "Security Assertion Markup Language (SAML)"
        })
    }
}