use crate::config::RedirectFilterConf;
use crate::filters::{Context, Filter};
use crate::path_match::PathMatch;
use anyhow::Result;
use hyper::{header, Body, Request, Response, StatusCode};

pub struct RedirectFilter {
    location: String,
    matcher: PathMatch,
}

impl RedirectFilter {
    pub fn new(config: &RedirectFilterConf) -> Result<Self> {
        Ok(RedirectFilter {
            location: config.location.clone(),
            matcher: PathMatch::new(&config.paths, &config.not_paths)?,
        })
    }

    fn redirect(&self) -> Result<Response<Body>> {
        Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, &self.location)
            .body(Body::empty())?)
    }
}

#[async_trait::async_trait]
impl Filter for RedirectFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        let path = req.uri().path();

        if self.matcher.matches(path)? {
            return self.redirect();
        }

        if let Some(enc) = req.headers().get(header::ACCEPT_ENCODING) {
            let mime: mime::Mime = enc.to_str()?.parse()?;
            if mime.type_() == mime::TEXT {
                return self.redirect();
            }
        }

        ctx.next(req).await
    }
}
