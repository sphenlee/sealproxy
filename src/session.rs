use anyhow::Result;
use cookie::{Cookie, SameSite};
use hyper::header::{self, HeaderValue};
use hyper::{Body, Response};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

pub const AUDIENCE: &str = "authnproxy";
pub const SESSION_COOKIE: &str = "sid";

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub exp: i64,
}

pub fn establish_session(mut resp: Response<Body>, mut claims: Claims) -> Result<Response<Body>> {
    // TODO - store this in config and load the key only at startup
    let pem = std::fs::read("private.pem")?;
    let encoding_key = EncodingKey::from_rsa_pem(pem.as_ref())?;

    claims.exp = (OffsetDateTime::now_utc() + Duration::days(1)).unix_timestamp();

    let header = Header::new(Algorithm::RS256);
    let jwt = jsonwebtoken::encode(&header, &claims, &encoding_key)?;

    let cookie = Cookie::build(SESSION_COOKIE, jwt)
        .secure(false) // TODO - unsecure until HTTPS is enabled by default
        .same_site(SameSite::Strict)
        .max_age(Duration::days(1))
        .finish();

    let header = HeaderValue::from_str(cookie.to_string().as_ref())?;
    resp.headers_mut().insert(header::SET_COOKIE, header);

    Ok(resp)
}