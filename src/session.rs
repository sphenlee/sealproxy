use crate::state::State;
use anyhow::Result;
use cookie::{Cookie, SameSite};
use hyper::header::{self, HeaderValue};
use hyper::{Body, Response};
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
    mut resp: Response<Body>,
    claims: Claims,
    state: &State,
) -> Result<Response<Body>> {
    let jwt_claims = JwtClaims {
        aud: AUDIENCE.to_owned(),
        iss: claims.issuer,
        sub: claims.subject,
        exp: (OffsetDateTime::now_utc() + Duration::days(1)).unix_timestamp(),
    };

    let header = Header::new(Algorithm::RS256);
    let jwt = jsonwebtoken::encode(&header, &jwt_claims, &state.session_key)?;

    let cookie = Cookie::build(SESSION_COOKIE, jwt)
        .secure(false) // TODO - unsecure until HTTPS is enabled by default
        .same_site(SameSite::Strict)
        .max_age(Duration::days(1))
        .finish();

    let header = HeaderValue::from_str(cookie.to_string().as_ref())?;
    resp.headers_mut().insert(header::SET_COOKIE, header);

    Ok(resp)
}
