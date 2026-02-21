use crate::auth::AuthZeroTokenVerifier;

pub struct SharedData {
    auth: AuthZeroTokenVerifier,
}

impl SharedData {
    pub fn new() -> Self {
        use std::env::var;

        let issuer = var("AUTHZERO_ISSUER").unwrap_or("https://lupyd.com/".to_string());
        let domain = var("AUTHZERO_DOMAIN").unwrap_or("lupyd.com".to_string());
        let audience = var("AUTHZERO_AUDIENCE").unwrap_or("https://lupyd.com".to_string());

        let auth = AuthZeroTokenVerifier::new(issuer, domain, audience);

        Self { auth }
    }
}
