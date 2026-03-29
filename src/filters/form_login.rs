use crate::config::FormLoginConf;
use crate::filters::{empty_body, Context, Filter};
use crate::session::Claims;
use crate::userbase::{get_user_base, DynUserBase, LookupResult};
use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header;
use hyper::{Method, Request, Response, StatusCode};
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
    pub fn new(config: &FormLoginConf) -> Result<Self> {
        Ok(Self {
            path: config.path.clone(),
            success_redirect: config.success_redirect.clone(),
            failure_redirect: config.failure_redirect.clone(),
            user_base: get_user_base(&config.user_base)?,
        })
    }

    fn redirect_or_reject(&self) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let response = if let Some(target) = &self.failure_redirect {
            Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header(header::LOCATION, target)
                .body(empty_body())?
        } else {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(empty_body())?
        };

        Ok(response)
    }
}

#[async_trait::async_trait]
impl Filter for FormLoginFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        if req.uri().path() != self.path {
            return ctx.next(req).await;
        }

        match *req.method() {
            Method::POST => {
                trace!("post to login path");
            }
            Method::GET => {
                // GET is passed to the backend to serve up the login page
                return ctx.finish(req).await;
            }
            _ => {
                let body = Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(empty_body())?;
                return Ok(body);
            }
        };

        let query = req.uri().query().map(str::to_owned);

        let bytes = req.collect().await?.to_bytes();

        let form: Form = serde_urlencoded::from_reader(bytes.reader())?;

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

                let ret = query.and_then(|q| {
                    url::form_urlencoded::parse(q.as_bytes())
                        .into_iter()
                        .find(|kv| kv.0 == "return")
                        .map(|(_k, v)| v.into_owned())
                });

                let redirect = ret
                    .or_else(|| self.success_redirect.clone())
                    .unwrap_or_else(|| "/".to_owned());

                let resp = Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header(header::LOCATION, &redirect)
                    .body(empty_body())?;

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
