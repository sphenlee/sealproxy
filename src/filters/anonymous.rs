use crate::config::AnonymousFilterConf;
use crate::filters::{Context, Filter};
use crate::r#match::Match;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{Request, Response};
use tracing::trace;

pub struct AnonymousFilter {
    matcher: Match,
}

impl AnonymousFilter {
    pub fn new(config: &AnonymousFilterConf) -> Result<Self> {
        Ok(AnonymousFilter {
            matcher: Match::new(&config.r#match)?,
        })
    }
}

#[async_trait::async_trait]
impl Filter for AnonymousFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        if self.matcher.matches_request(&req)? {
            let path = req.uri().path();
            trace!(%path, "allowing anonymous path");
            ctx.finish(req).await
        } else {
            ctx.next(req).await
        }
    }
}

