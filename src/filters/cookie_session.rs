use crate::config::CookieSessionFilterConf;
use crate::filters::{Context, Filter};
use crate::session::{Claims, JwtClaims, AUDIENCE, SESSION_COOKIE};
use crate::target::add_header_claims;
use anyhow::Result;
use cookie::Cookie;
use hyper::header;
use hyper::{Body, Request, Response};
use jsonwebtoken::{Algorithm, Validation};
use tracing::{debug, trace, warn};
use crate::state::State;

pub struct CookieSessionFilter {
}

impl CookieSessionFilter {
    pub fn new(_config: &CookieSessionFilterConf) -> Result<Self> {
        Ok(Self { })
    }

    fn get_cookie(&self, req: &Request<Body>, state: &State) -> Result<Option<JwtClaims>> {
        for val in req.headers().get_all(header::COOKIE) {
            let c = Cookie::parse(val.to_str()?)?;
            trace!(name = c.name(), "got cookie");

            if c.name() == SESSION_COOKIE {
                trace!("session cookie set");
                // TODO - centralise the JWT logic
                let mut validation = Validation::new(Algorithm::RS256);
                validation.set_audience(&[AUDIENCE]);

                let result = jsonwebtoken::decode(c.value(), &state.session_pub_key, &validation);
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
        if let Some(claims) = self.get_cookie(&req, &ctx.state)? {
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
