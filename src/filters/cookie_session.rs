use crate::config::CookieSessionFilterConf;
use crate::filters::{Context, Filter};
use crate::session::{Claims, JwtClaims, AUDIENCE, SESSION_COOKIE};
use crate::target::add_header_claims;
use anyhow::{Result, Context as _};
use cookie::Cookie;
use hyper::header;
use hyper::{Body, Request, Response};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use tracing::{debug, trace, warn};

pub struct CookieSessionFilter {
    decoding_key: DecodingKey<'static>,
}

impl CookieSessionFilter {
    pub fn new(config: &CookieSessionFilterConf) -> Result<Self> {
        let pem = std::fs::read(&config.public_key_file)
            .context(format!("error reading session public key file: {}", config.public_key_file))?;
        Ok(Self {
            decoding_key: DecodingKey::from_rsa_pem(pem.as_ref())?.into_static(),
        })
    }

    fn get_cookie(&self, req: &Request<Body>) -> Result<Option<JwtClaims>> {
        for val in req.headers().get_all(header::COOKIE) {
            let c = Cookie::parse(val.to_str()?)?;
            trace!(name = c.name(), "got cookie");

            if c.name() == SESSION_COOKIE {
                trace!("session cookie set");
                // TODO - centralise the JWT logic
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_audience(&[AUDIENCE]);

                let result = jsonwebtoken::decode(c.value(), &self.decoding_key, &validation);
                return Ok(match result {
                    Ok(jwt) => Some(jwt.claims),
                    Err(e) => {
                        warn!(error=?e, "invalid jwt");
                        None
                    }
                });
            }
        }

        return Ok(None);
    }
}

#[async_trait::async_trait]
impl Filter for CookieSessionFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, mut req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        if let Some(claims) = self.get_cookie(&req)? {
            debug!("valid session cookie provided");

            add_header_claims(
                &mut req,
                Claims {
                    issuer: claims.iss,
                    subject: claims.sub,
                },
            )?;

            ctx.finish(req).await
        } else {
            trace!("no session cookie provided");
            ctx.next(req).await
        }
    }
}
