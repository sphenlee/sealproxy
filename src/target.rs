use crate::config::Target;
use crate::filters::empty_body;
use crate::session::Claims;
use crate::upgrade::upgrade;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{header, StatusCode, Uri};
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use std::convert::TryInto;
use tracing::{error, info, trace};

pub fn add_header_claims(req: &mut Request<Incoming>, claims: Claims) -> Result<()> {
    let headers = req.headers_mut();
    headers.insert("X-Seal-Username", claims.subject.try_into()?);
    headers.insert("X-Seal-Mechanism", claims.issuer.try_into()?);

    Ok(())
}

#[tracing::instrument(skip(req, client, target))]
pub async fn route(
    mut req: Request<BoxBody<Bytes, hyper::Error>>,
    client: &Client<HttpConnector, BoxBody<Bytes, hyper::Error>>,
    target: &Target,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let path = req.uri().path();
    assert!(path.starts_with("/"));

    let mut url = target.url.join(&path[1..])?;
    url.set_query(req.uri().path_and_query().and_then(|pnq| pnq.query()));
    let uri: Uri = url.as_str().parse()?;

    info!(target=%url, "request");

    if req.headers().contains_key(header::UPGRADE) {
        trace!("client requested upgrade");
        upgrade(req, uri, client).await
    } else {
        *req.uri_mut() = uri;
        let resp = match client.request(req).await {
            Ok(resp) => resp.map(BodyExt::boxed),
            Err(err) => {
                error!("gateway error: {}", err);
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty_body())?
            }
        };

        info!(status=?resp.status(), "reply");
        Ok(resp)
    }
}
