use crate::config::AnonymousFilterConf;
use crate::filters::{Filter, Next};
use anyhow::Result;
use hyper::{Body, Request, Response};
use tracing::trace;
use crate::path_match::PathMatch;

pub struct AnonymousFilter {
    matcher: PathMatch
}

impl AnonymousFilter {
    pub fn new(config: &AnonymousFilterConf) -> Result<Self> {
        Ok(AnonymousFilter {
            matcher: PathMatch::new(&config.paths, &config.not_paths)?
        })
    }
}

#[async_trait::async_trait]
impl Filter for AnonymousFilter {
    #[tracing::instrument(skip(self, req, next))]
    async fn apply(
        &self,
        req: Request<Body>,
        next: Next<'_>,
    ) -> anyhow::Result<Response<Body>> {
        let path = req.uri().path();

        if self.matcher.matches(path)? {
            trace!(%path, "allowing anonymous path");
            next.finish(req).await
        } else {
            next.next(req).await
        }
    }
}
