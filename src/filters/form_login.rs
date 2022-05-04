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
    success_redirect: Option<String>,
    failure_redirect: Option<String>,
    user_base: Box<DynUserBase>,
}

impl FormLoginFilter {
    pub async fn new(config: &FormLoginConf) -> Result<Self> {
        Ok(Self {
            path: config.path.clone(),
            success_redirect: config.success_redirect.clone(),
            failure_redirect: config.failure_redirect.clone(),
            user_base: get_user_base(&config.user_base).await?,
        })
    }

    fn redirect_or_reject(&self) -> Result<Response<Body>> {
        if let Some(target) = &self.failure_redirect {
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
}

#[async_trait::async_trait]
impl Filter for FormLoginFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, mut req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        if req.uri().path() != self.path {
            return ctx.next(req).await;
        }

        match req.method() {
            &Method::POST => {
                trace!("post to login path");
            }
            &Method::GET => {
                // GET is passed to the backend to serve up the login page
                return ctx.finish(req).await;
            }
            _ => {
                return Ok(Response::builder()
                              .status(StatusCode::METHOD_NOT_ALLOWED)
                              .body(Body::empty())?);
            }
        };

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

                let ret= req.uri().query().and_then(|q|
                    url::form_urlencoded::parse(q.as_bytes())
                        .into_iter()
                        .find(|kv| kv.0 == "return")
                        .map(|(_k, v)| v.into_owned())
                );

                let redirect = ret
                    .or_else(|| self.success_redirect.clone())
                    .unwrap_or_else(|| "/".to_owned());

                let resp = Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header(header::LOCATION, &redirect)
                    .body(Body::empty())?;

                ctx.establish_session(resp, claims)
            }
            LookupResult::NoSuchUser => {
                debug!("user not found");
                self.redirect_or_reject()
            }
            LookupResult::IncorrectPassword => {
                debug!("incorrect password");
                self.redirect_or_reject()
            }
            LookupResult::Other(msg) => {
                debug!("something went wrong checking user base: {}", msg);
                self.redirect_or_reject()
            }
        }
    }
}
