use crate::config::AnonymousFilterConf;
use crate::filters::{Context, Filter};
use crate::path_match::PathMatch;
use anyhow::Result;
use hyper::{Body, Request, Response};
use tracing::trace;

pub struct AnonymousFilter {
    matcher: PathMatch,
}

impl AnonymousFilter {
    pub fn new(config: &AnonymousFilterConf) -> Result<Self> {
        Ok(AnonymousFilter {
            matcher: PathMatch::new(&config.paths, &config.not_paths)?,
        })
    }
}

#[async_trait::async_trait]
impl Filter for AnonymousFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        let path = req.uri().path();

        if self.matcher.matches(path)? {
            trace!(%path, "allowing anonymous path");
            ctx.finish(req).await
        } else {
            ctx.next(req).await
        }
    }
}
