use crate::state::State;
use anyhow::Result;
use bytes::Bytes;
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, SameSite};
use http_body_util::combinators::BoxBody;
use hyper::header::{self, HeaderValue};
use hyper::{Response};
use jsonwebtoken::{Algorithm, Header};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

pub const AUDIENCE: &str = "sealproxy";
pub const SESSION_COOKIE: &str = "seal.sid";

#[derive(Default, Clone)]
pub struct Claims {
    pub issuer: String,
    pub subject: String,
}

// TODO - don't expose this struct
#[derive(Serialize, Deserialize)]
pub struct JwtClaims {
    pub aud: String,
    pub iss: String,
    pub sub: String,
    pub exp: i64,
}

pub fn establish_session(
    mut resp: Response<BoxBody<Bytes, hyper::Error>>,
    claims: Claims,
    state: &State,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let jwt_claims = JwtClaims {
        aud: AUDIENCE.to_owned(),
        iss: claims.issuer,
        sub: claims.subject,
        exp: (OffsetDateTime::now_utc() + Duration::days(1)).unix_timestamp(),
    };

    let header = Header::new(Algorithm::RS256);
    let jwt = jsonwebtoken::encode(&header, &jwt_claims, &state.session_key)?;

    let cookie = Cookie::build(Cookie::new(SESSION_COOKIE, jwt))
        .secure(false) // TODO - unsecure until HTTPS is enabled by default
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::days(1))
        .to_string();

    let header = HeaderValue::from_str(&cookie)?;
    resp.headers_mut().append(header::SET_COOKIE, header);

    Ok(resp)
}
