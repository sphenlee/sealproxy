use crate::config::Target;
use crate::session::Claims;
use anyhow::Result;
use hyper::{client::HttpConnector, Client, Uri};
use hyper::{Body, Request, Response, header};
use std::convert::TryInto;
use tracing::{info, trace};
use crate::upgrade::upgrade;

pub fn add_header_claims(req: &mut Request<Body>, claims: Claims) -> Result<()> {
    let headers = req.headers_mut();
    headers.insert("X-Seal-Username", claims.subject.try_into()?);
    headers.insert("X-Seal-Mechanism", claims.issuer.try_into()?);

    Ok(())
}

#[tracing::instrument(skip(req, client, target))]
pub async fn route(
    mut req: Request<Body>,
    client: &Client<HttpConnector>,
    target: &Target,
) -> Result<Response<Body>> {
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
        let resp = client.request(req).await?;

        info!(status=?resp.status(), "reply");
        Ok(resp)
    }
}
