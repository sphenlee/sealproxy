use crate::config::BasicFilterConf;
use crate::filters::{Filter, Next};
use crate::session::{establish_session, Claims};
use crate::userbase::{get_user_base, DynUserBase, LookupResult};
use anyhow::Result;
use hyper::header;
use hyper::{Body, Request, Response, StatusCode};
use tracing::{debug, info, trace};
use crate::target::add_header_claims;

pub struct BasicFilter {
    user_base: Box<DynUserBase>,
}

impl BasicFilter {
    pub fn new(config: &BasicFilterConf) -> Result<BasicFilter> {
        Ok(BasicFilter {
            user_base: get_user_base(&config.user_base)?,
        })
    }
}

fn unauthorized() -> Result<Response<Body>> {
    Ok(Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, "Basic")
        .body(Body::empty())?)
}

struct BasicAuth {
    username: String,
    password: String,
}

fn get_basic_auth(req: &Request<Body>) -> Result<Option<BasicAuth>> {
    // TODO - fix this horrible if let cascade
    return if let Some(authn) = req.headers().get(header::AUTHORIZATION) {
        trace!("got Authorization header");

        if let Some(("Basic", userpass)) = authn.to_str()?.split_once(" ") {
            trace!("authorization is Basic");

            let decoded = String::from_utf8(base64::decode(userpass)?)?;

            if let Some((username, password)) = decoded.split_once(":") {
                trace!("Basic authorization is well-formed");

                Ok(Some(BasicAuth {
                    username: username.to_owned(),
                    password: password.to_owned(),
                }))
            } else {
                trace!("Basic authorization is not well-formed");
                Ok(None)
            }
        } else {
            trace!("Authorization is not Basic");
            Ok(None)
        }
    } else {
        trace!("Authorization header not present");
        Ok(None)
    };
}

#[async_trait::async_trait]
impl Filter for BasicFilter {
    #[tracing::instrument(skip(self, req, next))]
    async fn apply(
        &self,
        mut req: Request<Body>,
        next: Next<'_>,
    ) -> anyhow::Result<Response<Body>> {
        if let Some(basic_auth) = get_basic_auth(&req)? {
            return match self
                .user_base
                .lookup(&basic_auth.username, &basic_auth.password)
                .await?
            {
                LookupResult::NoSuchUser => {
                    debug!("user not found");
                    unauthorized()
                }
                LookupResult::IncorrectPassword => {
                    debug!("incorrect password");
                    unauthorized()
                }
                LookupResult::Success => {
                    info!("successful basic auth login");

                    let claims = Claims {
                        issuer: "seal/basic".to_owned(),
                        subject: basic_auth.username.clone(),
                    };

                    add_header_claims(&mut req, claims.clone())?;

                    let resp = next.finish(req).await?;
                    establish_session(resp, claims)
                }
                LookupResult::Other(msg) => {
                    debug!("something went wrong checking userbase: {}", msg);
                    unauthorized()
                }
            };
        }

        trace!("conditions not met, not using Basic authorization");
        unauthorized()
    }
}
