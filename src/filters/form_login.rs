use crate::config::FormLoginConf;
use crate::filters::{Context, Filter};
use crate::session::Claims;
use crate::userbase::{get_user_base, DynUserBase, LookupResult};
use anyhow::Result;
use hyper::header;
use hyper::{Body, Method, Request, Response, StatusCode};
use serde::Deserialize;
use tracing::{debug, info, trace};

#[derive(Deserialize)]
struct Form {
    username: String,
    password: String,
}

pub struct FormLoginFilter {
    path: String,
    success_redirect: String,
    failure_redirect: Option<String>,
    user_base: Box<DynUserBase>,
}

fn redirect_or_reject(redirect: Option<&str>) -> Result<Response<Body>> {
    if let Some(target) = redirect {
        Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, target)
            .body(Body::empty())?)
    } else {
        Ok(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())?)
    }
}

impl FormLoginFilter {
    pub fn new(config: &FormLoginConf) -> Result<Self> {
        Ok(Self {
            path: config.path.clone(),
            success_redirect: config.success_redirect.clone(),
            failure_redirect: config.failure_redirect.clone(),
            user_base: get_user_base(&config.user_base)?,
        })
    }
}

#[async_trait::async_trait]
impl Filter for FormLoginFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, mut req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        if req.uri().path() == self.path {
            if req.method() == Method::POST {
                trace!("post to login path");
                let body = hyper::body::to_bytes(req.body_mut()).await?;

                let form: Form = serde_urlencoded::from_bytes(body.as_ref())?;

                match self
                    .user_base
                    .lookup(&form.username, &form.password)
                    .await?
                {
                    LookupResult::Success => {
                        info!("successful form login");

                        let claims = Claims {
                            issuer: "seal/formlogin".to_owned(),
                            subject: form.username.clone(),
                        };
                        let resp = Response::builder()
                            .status(StatusCode::SEE_OTHER)
                            .header(header::LOCATION, &self.success_redirect)
                            .body(Body::empty())?;

                        ctx.establish_session(resp, claims)
                    }
                    LookupResult::NoSuchUser => {
                        debug!("user not found");
                        redirect_or_reject(self.failure_redirect.as_deref())
                    }
                    LookupResult::IncorrectPassword => {
                        debug!("incorrect password");
                        redirect_or_reject(self.failure_redirect.as_deref())
                    }
                    LookupResult::Other(msg) => {
                        debug!("something went wrong checking user base: {}", msg);
                        redirect_or_reject(self.failure_redirect.as_deref())
                    }
                }
            } else {
                ctx.finish(req).await
            }
        } else {
            ctx.next(req).await
        }
    }
}
