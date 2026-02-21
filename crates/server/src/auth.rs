use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use hyper::{HeaderMap, StatusCode, header};
use log::{error, info};
use ring::{rsa::PublicKeyComponents, signature::RSA_PKCS1_2048_8192_SHA256};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    lupyd_token::LupydTokenPermissions,
    utils::{EMULATOR_MODE, HTTP_CLIENT, get_current_timestamp_in_secs},
};

#[derive(Deserialize, Serialize)]
pub struct KeyHeader<'a> {
    pub kid: &'a str,
    pub alg: &'a str,
    pub typ: &'a str,
}

pub fn get_expiry_from_headers(headers: &HeaderMap) -> anyhow::Result<(u64, String)> {
    let last_modified = match headers.get(header::LAST_MODIFIED) {
        Some(val) => val.to_str()?.to_string(),
        None => httpdate::HttpDate::from(SystemTime::now()).to_string(),
    };

    let expiry = headers
        .get(header::EXPIRES)
        .map(|x| x.to_str().map(|y| httpdate::parse_http_date(y)));
    if let Some(Ok(Ok(exp))) = expiry {
        return Ok((
            exp.duration_since(UNIX_EPOCH).map(|x| x.as_secs())?,
            last_modified,
        ));
    }

    const MAX_AGE_STR: &str = "max-age=";
    let mut cache_duration = 0u64;
    if let Some(Ok(cache_control)) = headers.get(header::CACHE_CONTROL).map(|x| x.to_str()) {
        let directives = cache_control.split(',');
        for directive in directives {
            let directive = directive.trim();
            if let Some(value_str) = directive.strip_prefix(MAX_AGE_STR) {
                if let Ok(v) = value_str.parse() {
                    cache_duration = v;
                }
                break;
            }
        }
    }

    let date = headers
        .get(header::DATE)
        .context("Date Header is missing")?
        .to_str()?;
    let response_created_at = httpdate::parse_http_date(date)?;

    let expiry = response_created_at.duration_since(UNIX_EPOCH)?.as_secs() + cache_duration;

    Ok((expiry, last_modified))
}

#[derive(thiserror::Error, Debug)]
pub enum TokenVerificationError {
    #[error("Key with associated kid Not Found")]
    KeyNotFound,
    #[error("Token is expired")]
    TokenExpired,
    #[allow(unused)]
    #[error("Missing Username or Permissions")]
    MissingUsernameOrPermissions,
    #[error("Missing Authorization Header")]
    MissingAuthHeader,
    #[error("JSON parse error {0}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("Invalid Authorization Header")]
    InvalidAuthHeader,
    #[error("Invalid Firebase Project Id")]
    InvalidProjectId,
    #[error("Failed to Fetch Public Keys")]
    FailedToFetchKeys,
    #[error("Signature Verification Failed")]
    VerificationFailed,
    #[error("Invalid JWT")]
    InvalidJWT,
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct PublicJWK<'a> {
    kid: &'a str,
    n: &'a str,
    e: &'a str,

    // unused
    alg: &'a str,
    r#use: &'a str,
    x5t: &'a str,
    x5c: Vec<&'a str>,
}

#[derive(Deserialize, Debug)]
pub struct PublicJWKS<'a> {
    #[serde(borrow)]
    keys: Vec<PublicJWK<'a>>,
}

pub struct PublicKey {
    n: Vec<u8>,
    e: Vec<u8>,
    kid: Box<str>,
}

impl PublicKey {
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Option<()> {
        let public_key = PublicKeyComponents {
            n: &self.n,
            e: &self.e,
        };

        public_key
            .verify(&RSA_PKCS1_2048_8192_SHA256, payload, signature)
            .ok()
    }
}

#[allow(unused)]
#[derive(Deserialize, Debug)]
pub struct AuthZeroToken<'a> {
    #[serde(rename = "sub")]
    pub sub: &'a str,
    pub aud: Vec<&'a str>,
    pub iat: u64,
    pub exp: u64,
    pub iss: &'a str,

    #[serde(default)]
    pub uname: &'a str,
    #[serde(rename = "perms", default)]
    pub permissions: LupydTokenPermissions,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct AuthenticatedToken {
    pub username: Box<str>,

    pub permissions: LupydTokenPermissions,
    pub expiry: u64,
    pub user_id: Box<str>,
}

impl From<&AuthZeroToken<'_>> for AuthenticatedToken {
    fn from(value: &AuthZeroToken) -> Self {
        Self {
            username: value.uname.into(),
            permissions: value.permissions,
            expiry: value.exp,
            user_id: value.sub.into(),
        }
    }
}

pub struct AuthZeroTokenVerifier {
    public_keys: RwLock<(Vec<PublicKey>, u64, String)>,
    issuer: Box<str>,
    domain: Box<str>,
    audience: Box<str>,
}

impl AuthZeroTokenVerifier {
    pub fn new(
        issuer: impl Into<Box<str>>,
        domain: impl Into<Box<str>>,
        audience: impl Into<Box<str>>,
    ) -> Self {
        Self {
            public_keys: RwLock::new((Vec::new(), 0, String::new())),
            issuer: issuer.into(),
            domain: domain.into(),
            audience: audience.into(),
        }
    }

    pub async fn verify_from_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedToken, TokenVerificationError> {
        let bearer_token = headers
            .get(header::AUTHORIZATION)
            .ok_or(TokenVerificationError::MissingAuthHeader)?
            .to_str()
            .map_err(|_| TokenVerificationError::InvalidAuthHeader)?;

        let token = bearer_token
            .strip_prefix("Bearer ")
            .ok_or(TokenVerificationError::InvalidAuthHeader)?;

        self.verify(token).await
    }

    pub async fn verify(&self, token: &str) -> Result<AuthenticatedToken, TokenVerificationError> {
        if EMULATOR_MODE {
            if std::env::var("NO_TOKEN_VERIFICATION").unwrap_or_default() == "true" {
                log::warn!("NO_TOKEN_VERIFICATION is set to true, skipping token verification");
                return Ok(AuthenticatedToken {
                    username: token.into(),
                    permissions: LupydTokenPermissions::LUPYD_USER,
                    expiry: get_current_timestamp_in_secs() + 3600,
                    user_id: token.into(),
                });
            }
        }

        let (payload, signature) = token
            .rsplit_once('.')
            .ok_or(TokenVerificationError::InvalidAuthHeader)?;
        let (header, body) = payload
            .split_once('.')
            .ok_or(TokenVerificationError::InvalidAuthHeader)?;

        let buf = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| TokenVerificationError::InvalidJWT)?;
        let decoded_token: AuthZeroToken = serde_json::from_slice(&buf)?;

        if decoded_token.exp < get_current_timestamp_in_secs() {
            return Err(TokenVerificationError::TokenExpired);
        }

        info!(
            "decoded_token: {:?}, expected issuer: {}",
            decoded_token, self.issuer
        );

        if decoded_token.uname.is_empty() || decoded_token.permissions.value() == 0 {
            return Err(TokenVerificationError::MissingUsernameOrPermissions);
        }

        if decoded_token.iss != self.issuer.as_ref()
            || decoded_token
                .aud
                .iter()
                .all(|x| *x != self.audience.as_ref())
        {
            // TODO: Rename errors
            return Err(TokenVerificationError::InvalidProjectId);
        }

        let buf = URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| TokenVerificationError::InvalidJWT)?;

        let raw_signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TokenVerificationError::InvalidJWT)?;
        let header: KeyHeader = serde_json::from_slice(&buf)?;

        {
            let mut guard = self.public_keys.read().await;

            let key = guard.0.iter().find(|x| x.kid.as_ref() == header.kid);

            let key = match key {
                Some(key) => key,
                None => {
                    if guard.1 < get_current_timestamp_in_secs() {
                        drop(guard);
                        let _ = self
                            .refresh_public_keys()
                            .await
                            .map_err(|_| TokenVerificationError::FailedToFetchKeys);
                        guard = self.public_keys.read().await;

                        guard
                            .0
                            .iter()
                            .find(|x| x.kid.as_ref() == header.kid)
                            .ok_or(TokenVerificationError::KeyNotFound)?
                    } else {
                        return Err(TokenVerificationError::KeyNotFound);
                    }
                }
            };

            key.verify(payload.as_bytes(), &raw_signature)
                .ok_or(TokenVerificationError::VerificationFailed)?;

            let token = AuthenticatedToken::from(&decoded_token);

            return Ok(token);
        }
    }

    pub async fn refresh_public_keys(&self) -> anyhow::Result<()> {
        let mut guard = self.public_keys.write().await;
        let mut uri = String::with_capacity(64);
        uri.push_str("https://");
        uri.push_str(&self.domain);
        uri.push_str("/.well-known/jwks.json");

        let mut response_builder = HTTP_CLIENT.get(uri);

        if !guard.2.is_empty() {
            response_builder = response_builder.header(header::IF_MODIFIED_SINCE, guard.2.clone());
        }

        let response = response_builder.send().await?;

        if response.status() == StatusCode::NOT_MODIFIED {
            let (expiry, last_modified) = get_expiry_from_headers(response.headers())?;
            guard.1 = expiry;
            guard.2 = last_modified;
            return Ok(());
        }

        if response.status() != StatusCode::OK {
            return Err(anyhow::anyhow!(format!(
                "Received unexpected statuscode {}",
                response.status()
            )));
        }

        let (expiry, last_modified) = get_expiry_from_headers(response.headers())?;

        let body = response.text().await?;
        let keys = serde_json::from_str::<PublicJWKS>(&body)?;

        info!("Got Public Keys: {:?}, expires at {}", keys, expiry);
        guard.0.clear();
        for key in keys.keys {
            let e = URL_SAFE_NO_PAD.decode(key.e)?;
            let n = URL_SAFE_NO_PAD.decode(key.n)?;
            let kid: Box<str> = key.kid.into();

            guard.0.push(PublicKey { e, n, kid });
        }

        guard.1 = expiry;
        guard.2 = last_modified;

        Ok(())
    }
}
