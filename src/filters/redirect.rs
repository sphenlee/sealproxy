use crate::config::RedirectFilterConf;
use crate::filters::{Context, Filter};
use crate::path_match::PathMatch;
use anyhow::Result;
use hyper::{header, Body, Request, Response, StatusCode};

pub struct RedirectFilter {
    location: String,
    with_return: bool,
    matcher: PathMatch,
}

impl RedirectFilter {
    pub fn new(config: &RedirectFilterConf) -> Result<Self> {
        Ok(RedirectFilter {
            location: config.location.clone(),
            with_return: config.with_return,
            matcher: PathMatch::new(&config.paths, &config.not_paths)?,
        })
    }

    fn redirect(&self, req: &Request<Body>) -> Result<Response<Body>> {
        let mut url = self.location.clone();
        if self.with_return {
            let ret = req.uri().to_string();

            let q = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("return", &ret)
                .finish();

            url.push('?');
            url.push_str(&q);
        }

        Ok(Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, url.as_str())
            .body(Body::empty())?)
    }
}

#[async_trait::async_trait]
impl Filter for RedirectFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(&self, req: Request<Body>, ctx: Context<'_>) -> Result<Response<Body>> {
        let path = req.uri().path();

        if self.matcher.matches(path)? {
            return self.redirect(&req);
        }

        if let Some(header_val) = req.headers().get(header::ACCEPT) {
            let accept = header_val.to_str()?;
            // NOTE - this is not technically correct because Accept header is allowed
            // to include a quoted string (with embedded commas) in the extension params
            // but these seem super rare in practice. If we see one of these it should
            // fail to parse and get ignored anyway.
            for part in accept.split(",") {
                if let Ok(mime) = part.parse::<mime::Mime>() {
                    if mime.type_() == mime::TEXT {
                        return self.redirect(&req);
                    }
                }
            }
        }

        ctx.next(req).await
    }
}
