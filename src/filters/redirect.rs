use crate::config::RedirectFilterConf;
use crate::filters::{empty_body, Context, Filter};
use crate::r#match::Match;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::{header, Request, Response, StatusCode};

pub struct RedirectFilter {
    location: String,
    with_return: bool,
    matcher: Match,
}

impl RedirectFilter {
    pub fn new(config: &RedirectFilterConf) -> Result<Self> {
        Ok(RedirectFilter {
            location: config.location.clone(),
            with_return: config.with_return,
            matcher: Match::new(&config.r#match)?,
        })
    }

    fn redirect(&self, req: &Request<Incoming>) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let mut url = self.location.clone();
        if self.with_return {
            let ret = req.uri().to_string();

            let q = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("return", &ret)
                .finish();

            url.push('?');
            url.push_str(&q);
        }

        let response = Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(header::LOCATION, url.as_str())
            .body(empty_body())?;
        Ok(response)
    }
}

#[async_trait::async_trait]
impl Filter for RedirectFilter {
    #[tracing::instrument(skip(self, req, ctx))]
    async fn apply(
        &self,
        req: Request<Incoming>,
        ctx: Context<'_>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        if self.matcher.matches_request(&req)? {
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
